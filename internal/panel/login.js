'use strict';
/* 登录页交互：POST /panel/api/auth/login → 成功后整页跳转到 /panel/。
   本文件独立于 app.js（登录页没有管理面板 DOM），同样不依赖内联脚本。 */
(function () {
  var form = document.getElementById('loginForm');
  var user = document.getElementById('username');
  var pass = document.getElementById('password');
  var err = document.getElementById('err');
  var btn = document.getElementById('submit');
  if (!form) return;

  function show(msg) {
    err.textContent = msg;
    err.hidden = false;
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    err.hidden = true;
    var name = user.value.trim();
    if (!name || !pass.value) {
      show('请输入用户名和密码');
      return;
    }
    btn.disabled = true;
    try {
      var r = await fetch('/panel/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: name, password: pass.value })
      });
      if (r.ok) {
        location.replace('/panel/');
        return;
      }
      var d = await r.json().catch(function () { return {}; });
      if (r.status === 429) show('尝试次数过多，请 5 分钟后再试');
      else if (r.status === 503) show('面板用户存储不可用，请联系管理员查看服务端日志');
      else if (d.error === 'invalid_credentials') show('用户名或密码错误');
      else show(d.error || ('登录失败（HTTP ' + r.status + '）'));
    } catch (_) {
      show('网络错误，请重试');
    }
    btn.disabled = false;
    pass.select();
  });
})();
