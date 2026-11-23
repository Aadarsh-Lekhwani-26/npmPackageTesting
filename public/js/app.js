/**
 * ArgonCore Integration Demo — Client Application
 *
 * Interacts with Express API endpoints backed directly by the published
 * 'argoncore' npm package.
 */

// Global state cache
let registeredUsers = [];
let activeServerPolicy = { memoryCost: 1024, timeCost: 1, parallelism: 1, version: 19 };

document.addEventListener('DOMContentLoaded', () => {
  initEventListeners();
  loadUsers();
  loadPolicy();
  loadSampleHashToInspect();
});

function initEventListeners() {
  // Registration form
  const regForm = document.getElementById('register-form');
  if (regForm) {
    regForm.addEventListener('submit', handleRegister);
  }

  // Login form
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', handleLogin);
  }
}

// -----------------------------------------------------------------------------
// Terminal Logging Helper
// -----------------------------------------------------------------------------
function logToTerminal(title, payload, isSuccess = true) {
  const terminal = document.getElementById('auth-terminal-output');
  const pill = document.getElementById('auth-status-pill');
  const timestamp = new Date().toLocaleTimeString();

  let formatted = `[${timestamp}] ▶ ${title.toUpperCase()}\n`;
  formatted += `------------------------------------------------------------\n`;
  if (typeof payload === 'object') {
    formatted += JSON.stringify(payload, null, 2);
  } else {
    formatted += payload;
  }
  formatted += `\n\n` + terminal.textContent;

  terminal.textContent = formatted;

  if (pill) {
    pill.textContent = isSuccess ? 'Success' : 'Error / Failed';
    pill.style.color = isSuccess ? 'var(--success)' : 'var(--danger)';
  }
}

// -----------------------------------------------------------------------------
// Registration Handler
// -----------------------------------------------------------------------------
async function handleRegister(e) {
  e.preventDefault();
  const usernameInput = document.getElementById('reg-username');
  const passwordInput = document.getElementById('reg-password');
  const profileInput = document.getElementById('reg-profile');
  const submitBtn = document.getElementById('reg-submit-btn');

  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  const profile = profileInput.value;

  submitBtn.disabled = true;
  submitBtn.innerHTML = `<span>Hashing with ArgonCore...</span>`;

  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, profile })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Registration failed');
    }

    logToTerminal('Registration Succeeded', {
      username: data.data.username,
      hashGenerated: data.data.hashPreview,
      durationMs: `${data.data.durationMs} ms`,
      parametersUsed: data.data.parametersUsed,
      message: data.message
    }, true);

    // Populate inspector and lab with newly created hash
    setLabHash(data.data.hashPreview);

    // Pre-fill login
    document.getElementById('login-username').value = username;
    document.getElementById('login-password').value = password;

    // Refresh store
    await loadUsers();
    passwordInput.value = '';
  } catch (err) {
    logToTerminal('Registration Failed', { error: err.message }, false);
    alert(`Registration Error: ${err.message}`);
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<span>Register User &amp; Hash Password</span>`;
  }
}

// -----------------------------------------------------------------------------
// Login Handler
// -----------------------------------------------------------------------------
async function handleLogin(e) {
  e.preventDefault();
  const usernameInput = document.getElementById('login-username');
  const passwordInput = document.getElementById('login-password');
  const submitBtn = document.getElementById('login-submit-btn');

  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  submitBtn.disabled = true;
  submitBtn.innerHTML = `<span>Verifying with ArgonCore...</span>`;

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Authentication rejected');
    }

    logToTerminal('Authentication Result', {
      authenticated: data.data.authenticated,
      username: data.data.username,
      verifyDurationMs: `${data.data.verifyDurationMs} ms (Constant Time)`,
      rehashEvaluation: data.data.rehash.triggered
        ? '⚠️ POLICY UPGRADE TRIGGERED — User hash was automatically recomputed & updated!'
        : '✅ Parameters meet active security policy (no rehash required)',
      rehashDetails: data.data.rehash,
      message: data.message
    }, true);

    // Refresh user store to reflect updated rehash count or last login
    await loadUsers();
  } catch (err) {
    logToTerminal('Authentication Rejected', {
      authenticated: false,
      error: err.message,
      note: 'Constant-time verification rejected credentials or user does not exist.'
    }, false);
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<span>Authenticate Credentials</span>`;
  }
}

// -----------------------------------------------------------------------------
// Deliberate Incorrect Password Test
// -----------------------------------------------------------------------------
function testIncorrectPassword() {
  const usernameInput = document.getElementById('login-username');
  const passwordInput = document.getElementById('login-password');

  if (!usernameInput.value.trim()) {
    usernameInput.value = 'alice';
  }
  passwordInput.value = 'DeliberatelyIncorrectPassword999!';
  document.getElementById('login-form').dispatchEvent(new Event('submit'));
}

// -----------------------------------------------------------------------------
// Quick Fill Helper
// -----------------------------------------------------------------------------
function quickFill(username, password) {
  document.getElementById('login-username').value = username;
  document.getElementById('login-password').value = password;
}

function togglePasswordVisibility(inputId) {
  const input = document.getElementById(inputId);
  if (input) {
    input.type = input.type === 'password' ? 'text' : 'password';
  }
}

// -----------------------------------------------------------------------------
// User Store Listing
// -----------------------------------------------------------------------------
async function loadUsers() {
  const tbody = document.getElementById('users-tbody');
  const countBadge = document.getElementById('user-count-badge');

  try {
    const res = await fetch('/api/auth/users');
    const data = await res.json();
    registeredUsers = data.users || [];

    countBadge.textContent = `${registeredUsers.length} Users`;

    if (registeredUsers.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No users registered yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = registeredUsers.map(user => {
      const details = user.hashDetails || {};
      const rehashBadge = user.rehashCount > 0
        ? `<span class="badge badge-warning" title="Rehashed ${user.rehashCount} time(s)">Rehashed x${user.rehashCount}</span>`
        : `<span class="badge badge-neutral">Original</span>`;

      return `
        <tr>
          <td><strong>${escapeHtml(user.username)}</strong></td>
          <td><code>${details.memoryCost || '—'} KiB</code></td>
          <td><code>t=${details.timeCost || '—'}</code></td>
          <td><code>p=${details.parallelism || '—'}</code></td>
          <td>${rehashBadge}</td>
          <td>
            <span class="hash-snippet" title="${escapeHtml(user.hash)}">${escapeHtml(user.hash)}</span>
            <button class="btn-chip" onclick="copyToClipboard('${escapeHtml(user.hash)}')" title="Copy MCF hash">Copy</button>
          </td>
          <td>
            <div class="table-actions">
              <button class="btn btn-sm btn-secondary" onclick="inspectSpecificHash('${escapeHtml(user.hash)}')">Inspect</button>
              <button class="btn btn-sm btn-secondary" onclick="loadUserToLab('${escapeHtml(user.username)}', '${escapeHtml(user.hash)}')">Lab</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Failed to load users: ${escapeHtml(err.message)}</td></tr>`;
  }
}

async function resetUserStore() {
  if (!confirm('Reset in-memory user store to default seed accounts (alice & bob)?')) {
    return;
  }
  try {
    const res = await fetch('/api/auth/reset', { method: 'POST' });
    const data = await res.json();
    logToTerminal('User Store Reset', data, true);
    await loadUsers();
  } catch (err) {
    alert(`Reset error: ${err.message}`);
  }
}

// -----------------------------------------------------------------------------
// Server Policy Configuration
// -----------------------------------------------------------------------------
async function loadPolicy() {
  try {
    const res = await fetch('/api/auth/policy');
    const data = await res.json();
    if (data.policy) {
      activeServerPolicy = data.policy;
      document.getElementById('policy-memory').value = activeServerPolicy.memoryCost;
      document.getElementById('policy-time').value = activeServerPolicy.timeCost;
      document.getElementById('policy-parallelism').value = activeServerPolicy.parallelism;
    }
  } catch (err) {
    console.error('Failed to load server policy:', err);
  }
}

async function updateServerPolicy(e) {
  e.preventDefault();
  const m = parseInt(document.getElementById('policy-memory').value, 10);
  const t = parseInt(document.getElementById('policy-time').value, 10);
  const p = parseInt(document.getElementById('policy-parallelism').value, 10);

  try {
    const res = await fetch('/api/auth/policy', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ memoryCost: m, timeCost: t, parallelism: p })
    });
    const data = await res.json();

    if (!res.ok) throw new Error(data.error);

    activeServerPolicy = data.policy;
    logToTerminal('Server Policy Updated', {
      newPolicy: activeServerPolicy,
      note: 'Next logins will check against this policy with needsRehash(). If stored hash is weaker, auto-rehash triggers!'
    }, true);
  } catch (err) {
    alert(`Failed to update policy: ${err.message}`);
  }
}

function setPolicyPreset(m, t, p) {
  document.getElementById('policy-memory').value = m;
  document.getElementById('policy-time').value = t;
  document.getElementById('policy-parallelism').value = p;
  document.getElementById('policy-form').dispatchEvent(new Event('submit'));
}

// -----------------------------------------------------------------------------
// Section 3: Hash Dissection & Inspection
// -----------------------------------------------------------------------------
function loadSampleHashToInspect() {
  const sample = '$argon2id$v=19$m=1024,t=1,p=1$rccxm1hySSQ2LDAIP5awuA$72nO+cY6UX1hm1D4xhSkk5bHwdIlJ8ag9c6hIg0o+qs';
  document.getElementById('inspector-input').value = sample;
  dissectHash();
}

function inspectSpecificHash(hash) {
  document.getElementById('inspector-input').value = hash;
  dissectHash();
  document.getElementById('inspector-section').scrollIntoView({ behavior: 'smooth' });
}

async function dissectHash() {
  const input = document.getElementById('inspector-input').value.trim();
  if (!input) return;

  try {
    const res = await fetch('/api/demo/parse', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hash: input })
    });
    const data = await res.json();

    if (!data.data || !data.data.valid) {
      alert('Invalid or malformed Argon2 MCF string.');
      return;
    }

    const c = data.data.components;

    // Update Token Pills
    const container = document.getElementById('token-pills-container');
    container.innerHTML = `
      <span class="token-pill token-type" title="${escapeHtml(c.type.description)}">${escapeHtml(c.type.token)}</span>
      <span class="token-pill token-version" title="${escapeHtml(c.version.description)}">${escapeHtml(c.version.token)}</span>
      <span class="token-pill token-memory" title="${escapeHtml(c.parameters.description)}">${escapeHtml(c.parameters.token)}</span>
      <span class="token-pill token-salt" title="${escapeHtml(c.salt.description)}">${escapeHtml(c.salt.token)}</span>
      <span class="token-pill token-digest" title="${escapeHtml(c.digest.description)}">${escapeHtml(c.digest.token)}</span>
    `;

    // Update Breakdown Grid
    document.getElementById('comp-type-val').textContent = c.type.value;
    document.getElementById('comp-type-desc').textContent = c.type.description;

    document.getElementById('comp-ver-val').textContent = `v=${c.version.value} (0x${c.version.value.toString(16)})`;
    document.getElementById('comp-ver-desc').textContent = c.version.description;

    document.getElementById('comp-mem-val').textContent = c.parameters.memoryFormatted;
    document.getElementById('comp-mem-desc').textContent = `RAM block matrix size. Resistant to GPU parallelism.`;

    document.getElementById('comp-time-val').textContent = `${c.parameters.timeCost} Pass(es)`;
    document.getElementById('comp-time-desc').textContent = `Sequential iterations over memory block matrix.`;

    document.getElementById('comp-par-val').textContent = `${c.parameters.parallelism} Lane(s)`;
    document.getElementById('comp-par-desc').textContent = `Degree of parallelism / thread count.`;

    document.getElementById('comp-salt-val').textContent = `${c.salt.value.length} Base64 chars`;
    document.getElementById('comp-salt-desc').textContent = `Random salt preventing precomputed dictionary attacks.`;
  } catch (err) {
    console.error('Dissect error:', err);
  }
}

// -----------------------------------------------------------------------------
// Section 4: Laboratory verify() & needsRehash()
// -----------------------------------------------------------------------------
function setLabHash(hash) {
  document.getElementById('lab-verify-hash').value = hash;
  document.getElementById('lab-rehash-hash').value = hash;
}

function loadUserToLab(username, hash) {
  setLabHash(hash);
  document.getElementById('lab-verify-candidate').value = username === 'alice' ? 'AlicePass123!' : (username === 'bob' ? 'BobSecret456!' : '');
  document.getElementById('lab-section').scrollIntoView({ behavior: 'smooth' });
}

function loadAliceCandidate(correct) {
  const alice = registeredUsers.find(u => u.username.toLowerCase() === 'alice');
  if (alice) {
    document.getElementById('lab-verify-hash').value = alice.hash;
  }
  document.getElementById('lab-verify-candidate').value = correct ? 'AlicePass123!' : 'WrongCandidatePassword!';
}

async function runDirectVerify() {
  const hash = document.getElementById('lab-verify-hash').value.trim();
  const candidate = document.getElementById('lab-verify-candidate').value;
  const valElem = document.getElementById('verify-result-val');

  if (!hash) {
    alert('Please provide an encoded hash.');
    return;
  }

  valElem.textContent = 'Verifying in constant time...';
  valElem.className = 'lab-result-value';

  try {
    const res = await fetch('/api/demo/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hash, password: candidate })
    });
    const data = await res.json();

    if (data.data.match) {
      valElem.textContent = `✅ VALID MATCH (verify returned true in ${data.data.durationMs} ms)`;
      valElem.className = 'lab-result-value match-true';
    } else {
      valElem.textContent = `❌ MISMATCH / REJECTED (verify returned false in ${data.data.durationMs} ms)`;
      valElem.className = 'lab-result-value match-false';
    }
  } catch (err) {
    valElem.textContent = `Error: ${err.message}`;
    valElem.className = 'lab-result-value match-false';
  }
}

async function runDirectRehashCheck() {
  const hash = document.getElementById('lab-rehash-hash').value.trim();
  const m = parseInt(document.getElementById('lab-target-m').value, 10);
  const t = parseInt(document.getElementById('lab-target-t').value, 10);
  const p = parseInt(document.getElementById('lab-target-p').value, 10);

  const valElem = document.getElementById('rehash-result-val');
  const reasonsList = document.getElementById('rehash-reasons-list');

  if (!hash) {
    alert('Please provide an encoded hash to evaluate.');
    return;
  }

  valElem.textContent = 'Evaluating policy with needsRehash()...';
  valElem.className = 'lab-result-value';
  reasonsList.innerHTML = '';

  try {
    const res = await fetch('/api/demo/rehash-check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hash,
        targetPolicy: { memoryCost: m, timeCost: t, parallelism: p }
      })
    });
    const data = await res.json();
    const result = data.data;

    if (result.needsRehash) {
      valElem.textContent = `⚠️ TRUE — Hash parameters are weaker than target policy!`;
      valElem.className = 'lab-result-value match-false';
      reasonsList.innerHTML = result.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('');
    } else {
      valElem.textContent = `✅ FALSE — Hash meets or exceeds target policy standards.`;
      valElem.className = 'lab-result-value match-true';
      reasonsList.innerHTML = `<li>No rehash required. All cost parameters meet or exceed the target policy threshold.</li>`;
    }
  } catch (err) {
    valElem.textContent = `Error: ${err.message}`;
    valElem.className = 'lab-result-value match-false';
  }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    alert('Argon2 MCF hash copied to clipboard!');
  }).catch(() => {
    prompt('Copy hash:', text);
  });
}

function escapeHtml(str) {
  if (typeof str !== 'string') return String(str || '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
