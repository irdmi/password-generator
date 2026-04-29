(function () {
  const $ = id => document.getElementById(id);
  let currentPwd = '';

  function applyTheme(isDark) {
    document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
  }

  function initTheme() {
    const stored = localStorage.getItem('theme');
    if (stored) {
      applyTheme(stored === 'dark');
    }
    // Если нет stored — оставляем как есть (CSS обработает prefers-color-scheme)
    
    $('themeToggle').onclick = () => {
      const isDark = document.documentElement.getAttribute('data-theme') !== 'dark';
      applyTheme(isDark);
      localStorage.setItem('theme', isDark ? 'dark' : 'light');
    };
  }

  async function copyPwd() {
    if (!currentPwd) return;
    const btn = $('copy');
    const original = btn.textContent;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(currentPwd);
      } else {
        throw new Error('Fallback');
      }
      btn.textContent = '✓ Copied';
    } catch {
      const ta = document.createElement('textarea');
      ta.value = currentPwd;
      ta.style.position = 'fixed'; ta.style.left = '-9999px';
      document.body.appendChild(ta); ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      btn.textContent = '✓ Copied';
    }
    setTimeout(() => btn.textContent = original, 1400);
  }

  function generate() {
    try {
      currentPwd = PasswordUtils.generatePassword(
        Number($('length').value),
        {
          lower: $('lower').checked,
          upper: $('upper').checked,
          digits: $('digits').checked,
          symbols: $('symbols').checked,
          safe: $('safe').checked
        }
      );
      $('result').textContent = currentPwd;
      $('result').setAttribute('aria-label', `Password: ${currentPwd}`);
    } catch (e) {
      $('result').textContent = `⚠️ ${e.message}`;
      currentPwd = '';
    }
  }

  function handleHash() {
    const cfg = PasswordUtils.parseHash(window.location.hash);
    if (!cfg) return false;
    try {
      const pwd = PasswordUtils.generatePassword(cfg.length, cfg);
      document.body.classList.add('api-mode');
      document.body.innerHTML = cfg.json
        ? `<pre>${JSON.stringify({ password: pwd, length: cfg.length, generated_at: new Date().toISOString() }, null, 2)}</pre>`
        : `<pre>${pwd}</pre>`;
      // Копирование по клику в режиме API
      document.body.onclick = (e) => {
        if (e.target.tagName === 'PRE') {
          navigator.clipboard?.writeText(pwd);
          alert('✓ Copied');
        }
      };
    } catch (e) {
      document.body.classList.add('api-mode');
      document.body.innerHTML = `<pre style="color:#ef4444">Error: ${e.message}</pre>`;
    }
    return true;
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (handleHash()) return;
    initTheme();
    $('generate').onclick = generate;
    $('copy').onclick = copyPwd;
    // Enter в поле длины
    $('length').addEventListener('keypress', e => { if (e.key === 'Enter') generate(); });
    generate();
  });
})();
