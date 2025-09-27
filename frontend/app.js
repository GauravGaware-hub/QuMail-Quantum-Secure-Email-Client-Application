// app.js

let sessionToken = localStorage.getItem('qumail_token') || null;
const API_BASE = 'http://localhost:5001/api';

const setToken = (t) => {
  sessionToken = t;
  if (t) localStorage.setItem('qumail_token', t);
  else localStorage.removeItem('qumail_token');
};

const showApp = () => {
  document.getElementById('login-container').style.display = 'none';
  document.getElementById('app-container').style.display = 'block';
};

const showLogin = () => {
  document.getElementById('login-container').style.display = 'block';
  document.getElementById('app-container').style.display = 'none';
};

// Helper fetch with 401 handler
async function apiFetch(url, options) {
  const res = await fetch(url, options);
  if (res.status === 401) {
    setToken(null);
    showLogin();
    throw new Error('Unauthorized: please login again');
  }
  return res;
}

// LOGIN
document.getElementById('login-btn').addEventListener('click', async () => {
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value.trim();
  const msg = document.getElementById('login-msg');
  msg.textContent = '';
  if (!email || !password) {
    msg.textContent = 'Please fill all fields';
    msg.style.color = 'red';
    return;
  }
  try {
    const res = await apiFetch(`${API_BASE}/login`, {
      method: 'POST',
      credentials: 'include',             // send & receive cookies
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    if (res.ok && data.token) {
      setToken(data.token);  // optional if backend uses sessions
      msg.textContent = 'Login successful!';
      msg.style.color = 'green';
      showApp();
      loadInbox();
    } else {
      msg.textContent = data.error || 'Login failed';
      msg.style.color = 'red';
    }
  } catch (e) {
    msg.textContent = 'Network error: ' + e.message;
    msg.style.color = 'red';
  }
});

// LOGOUT
document.getElementById('logout-btn').addEventListener('click', () => {
  setToken(null);
  showLogin();
});

// SEND EMAIL
document.getElementById('send-btn').addEventListener('click', async () => {
  const sendBtn = document.getElementById('send-btn');
  sendBtn.disabled = true;

  const msgEl = document.getElementById('send-msg');
  msgEl.className = '';  // reset any class before new message
  msgEl.textContent = '';
  msgEl.style.color = '';

  if (!sessionToken) {
    msgEl.textContent = 'You must login to send emails.';
    msgEl.classList.add('alert', 'alert-danger');
    sendBtn.disabled = false;
    return;
  }

  const to = document.getElementById('to-email').value.trim();
  const subject = document.getElementById('subject').value.trim();
  const body = document.getElementById('body').value.trim();
  const securityLevel = document.getElementById('security-level')?.value || '4';

  if (!to || !body) {
    msgEl.textContent = 'To and body are required';
    msgEl.classList.add('alert', 'alert-danger');
    sendBtn.disabled = false;
    return;
  }

  const payload = { to, subject, body, securityLevel };

  const attachmentInput = document.getElementById('attachment');
  if (attachmentInput.files.length) {
    try {
      const file = attachmentInput.files[0];
      const b64 = await fileToBase64(file);
      const comma = b64.indexOf(',');
      payload.attachment = { name: file.name, b64: comma >= 0 ? b64.slice(comma + 1) : b64 };
    } catch {
      msgEl.textContent = 'Failed to read attachment';
      msgEl.classList.add('alert', 'alert-danger');
      sendBtn.disabled = false;
      return;
    }
  }

  try {
    const res = await apiFetch(`${API_BASE}/send`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (res.ok) {
      msgEl.textContent = 'Email sent successfully! ✓';
      msgEl.classList.add('alert', 'alert-success');
      document.getElementById('to-email').value = '';
      document.getElementById('subject').value = '';
      document.getElementById('body').value = '';
      attachmentInput.value = '';
    } else {
      msgEl.textContent = data.error || 'Send failed';
      msgEl.classList.add('alert', 'alert-danger');
    }
  } catch (e) {
    msgEl.textContent = 'Error: ' + e.message;
    msgEl.classList.add('alert', 'alert-danger');
  } finally {
    sendBtn.disabled = false;
  }
});


// LOAD INBOX
async function loadInbox() {
  const list = document.getElementById('email-list');
  list.innerHTML = '<li> Loading emails...</li>';

  if (!sessionToken) {
    list.innerHTML = '<li style="color:red;">Please login first to view inbox.</li>';
    return;
  }

  try {
    const res = await apiFetch(`${API_BASE}/inbox`, {
      method: 'GET',
      credentials: 'include'
      // no Authorization header needed since using cookie sessions
    });
    const data = await res.json();
    if (!res.ok) {
      list.innerHTML = `<li style="color:red">${data.error || 'Failed to load inbox'}</li>`;
      return;
    }
    list.innerHTML = '';
    const emails = data.emails || [];
    if (!emails.length) {
      list.innerHTML = '<li>No emails found</li>';
      return;
    }
    emails.forEach(e => {
      const li = document.createElement('li');
      li.innerHTML = `<strong>${e.from}</strong> — ${e.subject || '(no subject)'}<br>
                      <pre style="white-space:pre-wrap;margin-top:6px;">${e.body || ''}</pre>`;
      if (e.attachments) {
        e.attachments.forEach(att => {
          const a = document.createElement('a');
          const blob = base64ToBlob(att.b64);
          a.href = URL.createObjectURL(blob);
          a.download = att.name || 'attachment';
          a.textContent = `📎 ${att.name || 'file'}`;
          li.appendChild(document.createElement('br'));
          li.appendChild(a);
        });
      }
      list.appendChild(li);
    });
  } catch (e) {
    list.innerHTML = `<li style="color:red;">Error: ${e.message}</li>`;
  }
}

// UTILITIES
function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error('File read error'));
    reader.readAsDataURL(file);
  });
}
function base64ToBlob(b64) {
  const str = atob(b64 || '');
  const arr = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) arr[i] = str.charCodeAt(i);
  return new Blob([arr]);
}

// INITIAL STATE
if (sessionToken) {
  showApp();
  loadInbox();
} else {
  showLogin();
}

// REFRESH BUTTON
document.getElementById('refresh-btn')?.addEventListener('click', loadInbox);

