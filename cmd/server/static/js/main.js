const loginUrl = new URL('login', window.location.href);
const loginForm = document.getElementById('loginForm');
const username = document.getElementById('username');
const password = document.getElementById('password');
const error = document.getElementById('error');

const opener = window.opener;

const login = async () => {
  const resp = await fetch(loginUrl, {
    method: 'POST',
    body: JSON.stringify({
      username: username.value,
      password: password.value
    })
  });
  const body = await resp.text();
  if (resp.status !== 200) {
    console.error('Error', resp.status, body);
    error.innerText = body;
    return;
  }
  const paramaters = body;
  opener.postMessage(paramaters, '*');
  window.close();
}

if (opener) {
  loginForm.onsubmit = (e) => {
    e.preventDefault();
    login();
  }
}