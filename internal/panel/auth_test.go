package panel

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
)

// PBKDF2-HMAC-SHA256 必须与公开测试向量一致：自己实现的哈希若只做
// hash→verify 自洽测试，算法写错（例如块索引/异或顺序）也发现不了。
func TestPBKDF2SHA256Vectors(t *testing.T) {
	cases := []struct {
		iter int
		want string
	}{
		{1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), c.iter, 32))
		if got != c.want {
			t.Errorf("pbkdf2 iter=%d = %s, want %s", c.iter, got, c.want)
		}
	}
}

// newAuthTestPanel 构造启用面板登录的测试面板：临时用户文件 + 确定性管理员口令。
func newAuthTestPanel(t *testing.T, apiKey string) (*Panel, string) {
	t.Helper()
	dir := t.TempDir()
	usersFile := filepath.Join(dir, "panel_users.json")
	t.Setenv("PANEL_ADMIN_USER", "admin")
	t.Setenv("PANEL_ADMIN_PASSWORD", "admin-pass-123")
	p := New(Config{
		Version:   "test",
		APIKey:    apiKey,
		Pool:      pool.New(""),
		UsersFile: usersFile,
	})
	if p.authErr != nil {
		t.Fatalf("auth init: %v", p.authErr)
	}
	return p, usersFile
}

func doPanel(t *testing.T, p *Panel, method, path, body, bearer string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec
}

func loginCookie(t *testing.T, p *Panel, username, password string) *http.Cookie {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	rec := doPanel(t, p, "POST", "/panel/api/auth/login", string(body), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s: code=%d body=%s", username, rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			if !c.HttpOnly {
				t.Fatal("session cookie must be HttpOnly")
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("session cookie SameSite=%v want Lax", c.SameSite)
			}
			return c
		}
	}
	t.Fatal("login response missing session cookie")
	return nil
}

// 未登录访问 /panel/ 必须直接落到登录页，而不是把管理页面发出去。
func TestPanelIndexRedirectsToLogin(t *testing.T) {
	p, _ := newAuthTestPanel(t, "")
	rec := doPanel(t, p, "GET", "/panel/", "", "", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("GET /panel/ = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/panel/login" {
		t.Fatalf("Location=%q want /panel/login", loc)
	}
	// 登录页公开可用，且不含内联脚本（严格 CSP）。
	rec = doPanel(t, p, "GET", "/panel/login", "", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /panel/login = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="loginForm"`) {
		t.Fatalf("login page body: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `<script src="login.js"></script>`) {
		t.Fatal("login page must load login.js externally")
	}
	if strings.Contains(rec.Body.String(), "<script>") {
		t.Fatal("login page must not contain inline <script> (blocked by CSP)")
	}
}

// 登录成功后可访问页面与面板 API；错误口令返回 401 且不下发会话。
func TestPanelLoginFlow(t *testing.T) {
	p, _ := newAuthTestPanel(t, "")
	bad := doPanel(t, p, "POST", "/panel/api/auth/login", `{"username":"admin","password":"wrong"}`, "", nil)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("bad login = %d, want 401", bad.Code)
	}
	if len(bad.Result().Cookies()) != 0 {
		t.Fatal("failed login must not set a session cookie")
	}

	cookie := loginCookie(t, p, "admin", "admin-pass-123")

	rec := doPanel(t, p, "GET", "/panel/", "", "", cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "WorkBuddy2API") {
		t.Fatalf("logged-in GET /panel/ = %d", rec.Code)
	}

	rec = doPanel(t, p, "GET", "/panel/api/overview", "", "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("session overview = %d body=%s", rec.Code, rec.Body.String())
	}
	rec = doPanel(t, p, "GET", "/panel/api/overview", "", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous overview = %d, want 401", rec.Code)
	}

	// 已登录访问登录页 → 回面板。
	rec = doPanel(t, p, "GET", "/panel/login", "", "", cookie)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/panel/" {
		t.Fatalf("logged-in login page = %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}

	// 退出后会话立即失效。
	rec = doPanel(t, p, "POST", "/panel/api/auth/logout", "", "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d", rec.Code)
	}
	rec = doPanel(t, p, "GET", "/panel/api/auth/me", "", "", cookie)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("me after logout = %d, want 401", rec.Code)
	}
}

// api_key Bearer 仍是面板 API 的合法凭证（脚本/兼容路径），但不能匿名访问。
func TestPanelAPIKeyStillAuthorizesAPI(t *testing.T) {
	p, _ := newAuthTestPanel(t, "secret-key")
	rec := doPanel(t, p, "GET", "/panel/api/overview", "", "secret-key", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("api key overview = %d body=%s", rec.Code, rec.Body.String())
	}
	rec = doPanel(t, p, "GET", "/panel/api/auth/me", "", "secret-key", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("api key me = %d body=%s", rec.Code, rec.Body.String())
	}
}

// 用户管理：管理员可增删改，普通用户被拒；删除用户后其会话作废。
func TestPanelUserManagement(t *testing.T) {
	p, _ := newAuthTestPanel(t, "")
	admin := loginCookie(t, p, "admin", "admin-pass-123")

	rec := doPanel(t, p, "POST", "/panel/api/users",
		`{"username":"alice","password":"alice-pass-123","role":"user"}`, "", admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("create user = %d body=%s", rec.Code, rec.Body.String())
	}

	alice := loginCookie(t, p, "alice", "alice-pass-123")
	rec = doPanel(t, p, "GET", "/panel/api/users", "", "", alice)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin list = %d, want 403", rec.Code)
	}
	rec = doPanel(t, p, "GET", "/panel/api/users", "", "", admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin list = %d", rec.Code)
	}
	var listResp struct {
		Me    string          `json:"me"`
		Users []panelUserView `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	if listResp.Me != "admin" || len(listResp.Users) != 2 {
		t.Fatalf("list=%+v", listResp)
	}
	for _, u := range listResp.Users {
		if strings.Contains(u.Username, "pass") {
			t.Fatalf("unexpected user view: %+v", u)
		}
	}

	// 管理员重置 alice 密码 → alice 旧会话立即失效。
	rec = doPanel(t, p, "POST", "/panel/api/users/alice/password", `{"password":"alice-new-123"}`, "", admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset password = %d body=%s", rec.Code, rec.Body.String())
	}
	rec = doPanel(t, p, "GET", "/panel/api/auth/me", "", "", alice)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("old session after reset = %d, want 401", rec.Code)
	}
	loginCookie(t, p, "alice", "alice-new-123")

	// 不能删除自己；可以删除其他用户。
	rec = doPanel(t, p, "POST", "/panel/api/users/admin/delete", "", "", admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("delete self = %d, want 400", rec.Code)
	}
	rec = doPanel(t, p, "POST", "/panel/api/users/alice/delete", "", "", admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete alice = %d body=%s", rec.Code, rec.Body.String())
	}
}

// 修改自己的密码：旧口令校验、重置后续会话保持登录。
func TestPanelChangeOwnPassword(t *testing.T) {
	p, _ := newAuthTestPanel(t, "")
	cookie := loginCookie(t, p, "admin", "admin-pass-123")

	rec := doPanel(t, p, "POST", "/panel/api/auth/password",
		`{"current_password":"wrong","new_password":"new-pass-123"}`, "", cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong current = %d, want 400", rec.Code)
	}
	rec = doPanel(t, p, "POST", "/panel/api/auth/password",
		`{"current_password":"admin-pass-123","new_password":"new-pass-123"}`, "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("change password = %d body=%s", rec.Code, rec.Body.String())
	}
	// 响应重新签发会话：当前浏览器保持登录，旧 cookie 失效。
	var renewed *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			renewed = c
		}
	}
	if renewed == nil {
		t.Fatal("password change must re-issue session cookie")
	}
	if rec := doPanel(t, p, "GET", "/panel/api/auth/me", "", "", renewed); rec.Code != http.StatusOK {
		t.Fatalf("renewed session = %d, want 200", rec.Code)
	}
	if rec := doPanel(t, p, "GET", "/panel/api/auth/me", "", "", cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old session = %d, want 401", rec.Code)
	}
	loginCookie(t, p, "admin", "new-pass-123")
}

// 用户文件只落盘 PBKDF2 摘要，不出现明文口令；重启（重新加载）后仍可登录。
func TestPanelUsersFileHashesAndReloads(t *testing.T) {
	p, usersFile := newAuthTestPanel(t, "")
	loginCookie(t, p, "admin", "admin-pass-123")

	raw, err := os.ReadFile(usersFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "admin-pass-123") {
		t.Fatal("users file contains plaintext password")
	}
	if !strings.Contains(string(raw), "pbkdf2-sha256$") {
		t.Fatalf("users file missing password hash: %s", raw)
	}

	// 重新加载同一文件：管理员仍可用原口令登录。
	t.Setenv("PANEL_ADMIN_PASSWORD", "ignored-after-first-run")
	p2 := New(Config{Version: "test", Pool: pool.New(""), UsersFile: usersFile})
	if p2.authErr != nil {
		t.Fatalf("reload: %v", p2.authErr)
	}
	loginCookie(t, p2, "admin", "admin-pass-123")
}
