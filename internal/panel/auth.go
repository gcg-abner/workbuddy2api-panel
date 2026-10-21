// auth.go 面板账号体系：用户存储（PBKDF2 口令）、登录会话（HttpOnly Cookie）
// 与用户管理接口。
//
// 定位：api_key 是给网关 /v1/* 与脚本调用用的机器密钥；面板登录是给「人」用的
// 会话认证。两者互不替代：
//   - /panel/api/* 接受「有效 api_key Bearer」或「已登录会话 Cookie」；
//   - /panel/ 页面只认会话（浏览器导航无法携带 Bearer），未登录 302 到 /panel/login；
//   - api_key 为空时不再等于"面板开放"——面板 API 仍要求会话登录。
//
// 存储：data/panel_users.json（与 state_file 同目录），只存 PBKDF2-SHA256 口令摘要，
// 文件权限 0600，原子写。首次启动（文件不存在或没有用户）自动创建管理员：
//   PANEL_ADMIN_USER（缺省 admin）/ PANEL_ADMIN_PASSWORD（缺省随机生成并打印一次）。
//
// 会话：进程内 token→用户映射，24h 过期（Config.SessionTTL 可覆盖）；重启后需重新
// 登录。Cookie 为 HttpOnly + SameSite=Lax（阻断跨站 POST 携带会话），HTTPS 下自动
// 加 Secure。
package panel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/httpauth"
)

const (
	roleAdmin = "admin"
	roleUser  = "user"

	sessionCookieName = "wb2api_panel_session"
	defaultSessionTTL = 24 * time.Hour

	pbkdf2Iterations = 210000
	pbkdf2KeyLen     = 32
	pbkdf2SaltLen    = 16
	userFileVersion  = 1
)

// 用户管理错误（handler 据此映射 HTTP 状态）。
var (
	errInvalidUsername = errors.New("invalid_username")
	errInvalidPassword = errors.New("invalid_password")
	errInvalidRole     = errors.New("invalid_role")
	errUserExists      = errors.New("user_exists")
	errUserNotFound    = errors.New("user_not_found")
	errLastAdmin       = errors.New("last_admin")
	errBadPassword     = errors.New("bad_password")
)

// panelUser 一条面板用户记录（落盘形态；口令只存摘要）。
type panelUser struct {
	Username     string     `json:"username"`
	PasswordHash string     `json:"password_hash"`
	Role         string     `json:"role"` // admin / user
	CreatedAt    time.Time  `json:"created_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

// panelUserFile users JSON 文件顶层结构。
type panelUserFile struct {
	Version int          `json:"version"`
	Users   []*panelUser `json:"users"`
}

// userStore 用户集合（内存 + panel_users.json 原子落盘）。
type userStore struct {
	mu    sync.RWMutex
	path  string
	users map[string]*panelUser
}

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{1,31}$`)

func validUsername(s string) bool { return usernameRe.MatchString(s) }

// validPassword 口令强度下限：8–256 字节。上限只是防超大 body 的兜底。
func validPassword(s string) bool { return len(s) >= 8 && len(s) <= 256 }

func normalizeRole(role string) string {
	if role == roleAdmin {
		return roleAdmin
	}
	return roleUser
}

// dummyPasswordHash 未知用户名的等时口令校验：让"用户不存在"与"密码错误"
// 走同样的 PBKDF2 计算，避免通过响应时间枚举用户名。
var dummyPasswordHash = func() string {
	h, err := hashPassword("panel-unknown-user-timing-equalizer")
	if err != nil {
		return ""
	}
	return h
}()

// newUserStore 加载用户文件；文件不存在或用户为空时创建初始管理员。
func newUserStore(path string) (*userStore, error) {
	s := &userStore{path: path, users: map[string]*panelUser{}}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := s.bootstrapLocked(); err != nil {
			return nil, err
		}
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("read users file: %w", err)
	}
	// 空文件（手工 touch 过 / 异常中断留下空文件）按"尚无用户"处理，重新引导管理员。
	if strings.TrimSpace(string(raw)) == "" {
		if err := s.bootstrapLocked(); err != nil {
			return nil, err
		}
		return s, nil
	}
	var f panelUserFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse users file %s: %w", path, err)
	}
	hasAdmin := false
	for _, u := range f.Users {
		if u == nil || u.Username == "" {
			continue
		}
		u.Role = normalizeRole(u.Role)
		if u.Role == roleAdmin {
			hasAdmin = true
		}
		s.users[u.Username] = u
	}
	if len(s.users) == 0 {
		if err := s.bootstrapLocked(); err != nil {
			return nil, err
		}
		return s, nil
	}
	// 手工编辑/旧文件可能没有任何管理员：提升最早创建的用户，避免无人能管理。
	if !hasAdmin {
		var earliest *panelUser
		for _, u := range s.users {
			if earliest == nil || u.CreatedAt.Before(earliest.CreatedAt) {
				earliest = u
			}
		}
		if earliest != nil {
			earliest.Role = roleAdmin
			if err := s.saveLocked(); err != nil {
				return nil, fmt.Errorf("promote admin: %w", err)
			}
			log.Printf("panel: 用户文件中没有管理员，已将 %q 提升为管理员", earliest.Username)
		}
	}
	return s, nil
}

// bootstrapLocked 首次启动创建管理员（调用方保证尚未加锁）。
func (s *userStore) bootstrapLocked() error {
	username := strings.TrimSpace(os.Getenv("PANEL_ADMIN_USER"))
	if username == "" {
		username = "admin"
	}
	if !validUsername(username) {
		return fmt.Errorf("PANEL_ADMIN_USER %q 非法（2-32 位字母/数字/下划线/点/连字符）", username)
	}
	password := os.Getenv("PANEL_ADMIN_PASSWORD")
	generated := false
	if password == "" {
		var err error
		password, err = randomToken(18) // 24 字符，足够抵抗在线爆破
		if err != nil {
			return fmt.Errorf("generate admin password: %w", err)
		}
		generated = true
	} else if !validPassword(password) {
		return errors.New("PANEL_ADMIN_PASSWORD 至少需要 8 个字符")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}
	now := time.Now().UTC()
	s.users[username] = &panelUser{
		Username:     username,
		PasswordHash: hash,
		Role:         roleAdmin,
		CreatedAt:    now,
	}
	if err := s.saveLocked(); err != nil {
		delete(s.users, username)
		return fmt.Errorf("write users file: %w", err)
	}
	if generated {
		log.Printf("panel: 已创建初始管理员账号 %q，初始密码：%s（请登录后立即修改；可用 PANEL_ADMIN_USER / PANEL_ADMIN_PASSWORD 指定）", username, password)
	} else {
		log.Printf("panel: 已创建初始管理员账号 %q（密码取自 PANEL_ADMIN_PASSWORD）", username)
	}
	return nil
}

// saveLocked 原子落盘（tmp + rename），权限 0600。调用方需持有写锁（或初始化期）。
func (s *userStore) saveLocked() error {
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	users := make([]*panelUser, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	raw, err := json.MarshalIndent(panelUserFile{Version: userFileVersion, Users: users}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// get 返回用户副本（不暴露哈希给调用方之外的写路径）。
func (s *userStore) get(username string) *panelUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return nil
	}
	cp := *u
	return &cp
}

// authenticate 校验用户名口令。未知用户同样执行一次 PBKDF2（等时）。
func (s *userStore) authenticate(username, password string) *panelUser {
	s.mu.Lock()
	u, ok := s.users[username]
	var encoded string
	if ok {
		encoded = u.PasswordHash
	} else {
		encoded = dummyPasswordHash
	}
	s.mu.Unlock()

	if !verifyPassword(encoded, password) {
		return nil
	}
	if !ok {
		return nil
	}

	now := time.Now().UTC()
	s.mu.Lock()
	if cur, still := s.users[username]; still {
		cur.LastLoginAt = &now
		cp := *cur
		_ = s.saveLocked() // 最近登录时间仅展示，写失败不影响登录
		s.mu.Unlock()
		return &cp
	}
	s.mu.Unlock()
	return nil
}

// list 返回全部用户视图（按用户名排序，不含哈希）。
func (s *userStore) list() []panelUserView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]panelUserView, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, toUserView(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// countAdminsLocked 统计管理员数量（调用方需持锁）。
func (s *userStore) countAdminsLocked() int {
	n := 0
	for _, u := range s.users {
		if u.Role == roleAdmin {
			n++
		}
	}
	return n
}

func (s *userStore) create(username, password, role string) error {
	username = strings.TrimSpace(username)
	if !validUsername(username) {
		return errInvalidUsername
	}
	if !validPassword(password) {
		return errInvalidPassword
	}
	if role != roleAdmin && role != roleUser {
		return errInvalidRole
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[username]; exists {
		return errUserExists
	}
	u := &panelUser{Username: username, PasswordHash: hash, Role: role, CreatedAt: time.Now().UTC()}
	s.users[username] = u
	if err := s.saveLocked(); err != nil {
		delete(s.users, username)
		return err
	}
	return nil
}

func (s *userStore) remove(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.users[username]
	if !ok {
		return errUserNotFound
	}
	if old.Role == roleAdmin && s.countAdminsLocked() <= 1 {
		return errLastAdmin
	}
	delete(s.users, username)
	if err := s.saveLocked(); err != nil {
		s.users[username] = old
		return err
	}
	return nil
}

func (s *userStore) setPassword(username, password string) error {
	if !validPassword(password) {
		return errInvalidPassword
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return errUserNotFound
	}
	old := u.PasswordHash
	u.PasswordHash = hash
	if err := s.saveLocked(); err != nil {
		u.PasswordHash = old
		return err
	}
	return nil
}

func (s *userStore) changePassword(username, current, next string) error {
	if !validPassword(next) {
		return errInvalidPassword
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return errUserNotFound
	}
	if !verifyPassword(u.PasswordHash, current) {
		return errBadPassword
	}
	hash, err := hashPassword(next)
	if err != nil {
		return err
	}
	old := u.PasswordHash
	u.PasswordHash = hash
	if err := s.saveLocked(); err != nil {
		u.PasswordHash = old
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// 口令哈希（PBKDF2-HMAC-SHA256，标准库实现，不引入新依赖）
// ---------------------------------------------------------------------------

func hashPassword(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyLen)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

func verifyPassword(encoded, password string) bool {
	if encoded == "" {
		// 空摘要仍跑一次计算，保持耗时形状一致。
		_ = pbkdf2SHA256([]byte(password), make([]byte, pbkdf2SaltLen), pbkdf2Iterations, pbkdf2KeyLen)
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 10_000_000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// pbkdf2SHA256 按 RFC 8018 实现 PBKDF2（PRF=HMAC-SHA256）。
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	buf := make([]byte, 4)
	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(block))
		prf.Write(buf)
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// randomToken 生成 URL 安全随机串（会话 token / 初始密码）。
func randomToken(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ---------------------------------------------------------------------------
// 会话
// ---------------------------------------------------------------------------

type sessionEntry struct {
	username string
	expires  time.Time
}

type loginFailure struct {
	count int
	reset time.Time
}

// authManager 会话表 + 登录失败节流。用户角色每次请求都从 store 读取，
// 这样删除用户/改角色立即生效，不会留下旧会话的权限残留。
type authManager struct {
	users *userStore
	ttl   time.Duration

	mu       sync.Mutex
	sessions map[string]sessionEntry
	failures map[string]*loginFailure
}

const (
	maxLoginFailures   = 10
	loginFailureWindow = 5 * time.Minute
	maxFailureEntries  = 2048
	maxSessionsPerUser = 32
)

func newAuthManager(users *userStore, ttl time.Duration) *authManager {
	return &authManager{
		users:    users,
		ttl:      ttl,
		sessions: map[string]sessionEntry{},
		failures: map[string]*loginFailure{},
	}
}

func (a *authManager) newSession(username string) (string, time.Time, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now()
	exp := now.Add(a.ttl)
	a.mu.Lock()
	// 顺手回收过期会话：面板常驻进程，登录频次有限，线性扫描代价可忽略。
	for t, e := range a.sessions {
		if now.After(e.expires) {
			delete(a.sessions, t)
		}
	}
	// 单用户会话上限：防止同一账号反复登录导致进程内会话表无限增长。
	userSessions := 0
	for t, e := range a.sessions {
		if e.username != username {
			continue
		}
		userSessions++
		if userSessions >= maxSessionsPerUser {
			delete(a.sessions, t)
			userSessions--
		}
	}
	a.sessions[token] = sessionEntry{username: username, expires: exp}
	a.mu.Unlock()
	return token, exp, nil
}

func (a *authManager) dropSession(token string) {
	a.mu.Lock()
	delete(a.sessions, token)
	a.mu.Unlock()
}

// dropUserSessions 使某用户全部会话失效（改密/重置/删除时调用）。
func (a *authManager) dropUserSessions(username string) {
	a.mu.Lock()
	for t, e := range a.sessions {
		if e.username == username {
			delete(a.sessions, t)
		}
	}
	a.mu.Unlock()
}

// sessionUser 从 Cookie 解析当前用户；过期/用户已删除返回 nil。
func (a *authManager) sessionUser(r *http.Request) *panelUser {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	now := time.Now()
	a.mu.Lock()
	e, ok := a.sessions[c.Value]
	if ok && now.After(e.expires) {
		delete(a.sessions, c.Value)
		ok = false
	}
	a.mu.Unlock()
	if !ok {
		return nil
	}
	return a.users.get(e.username)
}

// allowLogin 登录失败节流：同一来源 5 分钟内失败 10 次后拒绝新尝试。
func (a *authManager) allowLogin(ip string) bool {
	if ip == "" {
		return true
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	f, ok := a.failures[ip]
	if !ok {
		return true
	}
	if now.After(f.reset) {
		delete(a.failures, ip)
		return true
	}
	return f.count < maxLoginFailures
}

func (a *authManager) noteFailure(ip string) {
	if ip == "" {
		return
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.failures) > maxFailureEntries {
		for k, v := range a.failures {
			if now.After(v.reset) {
				delete(a.failures, k)
			}
		}
		// 伪造 X-Forwarded-For 灌入大量唯一 IP 时，过期项可能清不干净：
		// 仍超限就丢弃任意条目，保证内存有界（被丢的 IP 只是失去计数，不失安全）。
		for k := range a.failures {
			if len(a.failures) <= maxFailureEntries/2 {
				break
			}
			delete(a.failures, k)
		}
	}
	f, ok := a.failures[ip]
	if !ok || now.After(f.reset) {
		a.failures[ip] = &loginFailure{count: 1, reset: now.Add(loginFailureWindow)}
		return
	}
	f.count++
}

func (a *authManager) noteSuccess(ip string) {
	if ip == "" {
		return
	}
	a.mu.Lock()
	delete(a.failures, ip)
	a.mu.Unlock()
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

type panelUserView struct {
	Username    string     `json:"username"`
	Role        string     `json:"role"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

func toUserView(u *panelUser) panelUserView {
	return panelUserView{Username: u.Username, Role: u.Role, CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt}
}

// identity 解析请求身份：会话优先，其次非空 api_key 的 Bearer。
// 返回 via = "session" / "api_key"。
func (p *Panel) identity(r *http.Request) (username, role, via string, ok bool) {
	if p.auth != nil {
		if u := p.auth.sessionUser(r); u != nil {
			return u.Username, u.Role, "session", true
		}
	}
	if key := p.apiKey(); key != "" && httpauth.VerifyBearer(r, key) {
		return "api-key", roleAdmin, "api_key", true
	}
	return "", "", "", false
}

func requestHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Ssl")), "on")
}

func requestIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
			return first
		}
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return xr
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

func (p *Panel) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/panel",
		HttpOnly: true,
		Secure:   requestHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
		MaxAge:   int(time.Until(exp).Seconds()),
	})
}

func (p *Panel) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/panel",
		HttpOnly: true,
		Secure:   requestHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

// authLogin POST /panel/api/auth/login {username,password}
func (p *Panel) authLogin(w http.ResponseWriter, r *http.Request) {
	if !p.loginEnabled() {
		writeErr(w, http.StatusNotImplemented, "面板登录未启用")
		return
	}
	if p.authErr != nil {
		writeErr(w, http.StatusServiceUnavailable, "面板用户存储不可用")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	ip := requestIP(r)
	if !p.auth.allowLogin(ip) {
		writeErr(w, http.StatusTooManyRequests, "too_many_attempts")
		return
	}
	if in.Username == "" || in.Password == "" {
		p.auth.noteFailure(ip)
		writeErr(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	u := p.auth.users.authenticate(in.Username, in.Password)
	if u == nil {
		p.auth.noteFailure(ip)
		writeErr(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	p.auth.noteSuccess(ip)
	token, exp, err := p.auth.newSession(u.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create session failed")
		return
	}
	p.setSessionCookie(w, r, token, exp)
	log.Printf("panel: 用户 %q 登录成功（ip=%s）", u.Username, ip)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": toUserView(u)})
}

// authLogout POST /panel/api/auth/logout（幂等）
func (p *Panel) authLogout(w http.ResponseWriter, r *http.Request) {
	if p.auth != nil {
		if c, err := r.Cookie(sessionCookieName); err == nil {
			p.auth.dropSession(c.Value)
		}
	}
	p.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// authMe GET /panel/api/auth/me 返回当前身份（未登录 401）。
func (p *Panel) authMe(w http.ResponseWriter, r *http.Request) {
	username, role, via, ok := p.identity(r)
	if !ok {
		// 未启用面板账号（旧装配）：api_key 为空即放行，与旧 withAuth 口径一致；
		// api_key 非空则回 invalid_api_key，前端据此弹原来的密钥输入框。
		if !p.loginEnabled() {
			if httpauth.VerifyBearer(r, p.apiKey()) {
				username, role, via = "api-key", roleAdmin, "legacy"
			} else {
				writeErr(w, http.StatusUnauthorized, "invalid_api_key")
				return
			}
		} else {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"user": map[string]any{
			"username": username,
			"role":     role,
			"via":      via,
		},
	})
}

// authChangePassword POST /panel/api/auth/password {current_password,new_password}
// 仅会话身份可改自己的密码；改完保留当前浏览器登录态（重新签发会话）。
func (p *Panel) authChangePassword(w http.ResponseWriter, r *http.Request) {
	username, _, via, ok := p.identity(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if via != "session" || p.auth == nil {
		writeErr(w, http.StatusBadRequest, "仅面板登录会话可修改密码")
		return
	}
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := p.auth.users.changePassword(username, in.CurrentPassword, in.NewPassword); err != nil {
		switch {
		case errors.Is(err, errBadPassword):
			writeErr(w, http.StatusBadRequest, "当前密码不正确")
		case errors.Is(err, errInvalidPassword):
			writeErr(w, http.StatusBadRequest, "新密码至少需要 8 个字符")
		default:
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	p.auth.dropUserSessions(username)
	old, _ := r.Cookie(sessionCookieName)
	if old != nil {
		p.auth.dropSession(old.Value)
	}
	token, exp, err := p.auth.newSession(username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create session failed")
		return
	}
	p.setSessionCookie(w, r, token, exp)
	log.Printf("panel: 用户 %q 修改了自己的密码", username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// requireAdmin 用户管理接口的权限门：仅会话管理员或 api_key 可操作。
func (p *Panel) requireAdmin(w http.ResponseWriter, r *http.Request) (username string, ok bool) {
	username, role, _, authed := p.identity(r)
	if !authed {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return "", false
	}
	if role != roleAdmin {
		writeErr(w, http.StatusForbidden, "仅管理员可管理用户")
		return "", false
	}
	if p.auth == nil {
		writeErr(w, http.StatusNotImplemented, "面板登录未启用")
		return "", false
	}
	return username, true
}

// userList GET /panel/api/users
func (p *Panel) userList(w http.ResponseWriter, r *http.Request) {
	me, ok := p.requireAdmin(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "me": me, "users": p.auth.users.list()})
}

// userCreate POST /panel/api/users {username,password,role}
func (p *Panel) userCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.requireAdmin(w, r); !ok {
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if in.Role == "" {
		in.Role = roleUser
	}
	if err := p.auth.users.create(in.Username, in.Password, in.Role); err != nil {
		writeUserError(w, err)
		return
	}
	log.Printf("panel: 新建面板用户 %q（角色 %s）", in.Username, in.Role)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// userDelete POST /panel/api/users/{username}/delete
func (p *Panel) userDelete(w http.ResponseWriter, r *http.Request) {
	me, ok := p.requireAdmin(w, r)
	if !ok {
		return
	}
	name := r.PathValue("username")
	if name == me {
		writeErr(w, http.StatusBadRequest, "不能删除当前登录的账号")
		return
	}
	if err := p.auth.users.remove(name); err != nil {
		writeUserError(w, err)
		return
	}
	p.auth.dropUserSessions(name)
	log.Printf("panel: 删除面板用户 %q（操作者 %q）", name, me)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// userSetPassword POST /panel/api/users/{username}/password {password}
func (p *Panel) userSetPassword(w http.ResponseWriter, r *http.Request) {
	me, ok := p.requireAdmin(w, r)
	if !ok {
		return
	}
	name := r.PathValue("username")
	var in struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := p.auth.users.setPassword(name, in.Password); err != nil {
		writeUserError(w, err)
		return
	}
	p.auth.dropUserSessions(name)
	if name == me {
		// 管理员重置自己的密码：保留当前浏览器登录（与"修改我的密码"一致）。
		token, exp, err := p.auth.newSession(name)
		if err == nil {
			p.setSessionCookie(w, r, token, exp)
		}
	}
	log.Printf("panel: 重置面板用户 %q 的密码（操作者 %q）", name, me)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func writeUserError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errInvalidUsername):
		writeErr(w, http.StatusBadRequest, "用户名需为 2-32 位字母/数字/下划线/点/连字符，且以字母或数字开头")
	case errors.Is(err, errInvalidPassword):
		writeErr(w, http.StatusBadRequest, "密码至少需要 8 个字符")
	case errors.Is(err, errInvalidRole):
		writeErr(w, http.StatusBadRequest, "角色只能是 admin 或 user")
	case errors.Is(err, errUserExists):
		writeErr(w, http.StatusConflict, "用户已存在")
	case errors.Is(err, errUserNotFound):
		writeErr(w, http.StatusNotFound, "用户不存在")
	case errors.Is(err, errLastAdmin):
		writeErr(w, http.StatusBadRequest, "至少需要保留一个管理员")
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}
