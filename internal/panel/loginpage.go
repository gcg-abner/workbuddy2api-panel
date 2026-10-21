// loginpage.go 登录页静态资源与入口。
//
// 未登录访问 /panel/ 时由 index 302 到 /panel/login；登录页本身只加载同源
// login.js（严格 CSP 禁止内联脚本）。已登录访问 /panel/login 会直接跳回面板。
package panel

import (
	_ "embed"
	"net/http"
)

//go:embed login.html
var loginHTML []byte

//go:embed login.js
var loginJS []byte

// loginEnabled 是否启用面板账号登录（配置了用户存储文件即为启用）。
// 未启用时保持旧行为（api_key 单因子/空 key 放行），仅供测试与兼容装配。
func (p *Panel) loginEnabled() bool { return p.cfg.UsersFile != "" }

// loginPage GET /panel/login
func (p *Panel) loginPage(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if !p.loginEnabled() {
		http.Redirect(w, r, "/panel/", http.StatusFound)
		return
	}
	if p.authErr != nil {
		http.Error(w, "面板用户存储初始化失败，请查看服务端日志", http.StatusInternalServerError)
		return
	}
	// 已登录（或携带有效 api_key）直接回面板。
	if _, _, _, ok := p.identity(r); ok {
		http.Redirect(w, r, "/panel/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(loginHTML)
}

// loginScript GET /panel/login.js
func (p *Panel) loginScript(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(loginJS)
}
