(() => {
  const rail = document.getElementById('rail');
  const contentsButton = document.getElementById('toc-toggle');
  contentsButton.addEventListener('click', () => {
    const open = rail.classList.toggle('open');
    contentsButton.setAttribute('aria-expanded', String(open));
  });
  const themeButton = document.getElementById('theme-toggle');
  const themes = ['system', 'light', 'dark'];
  let theme = 'system';
  const applyTheme = () => {
    if (theme === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', theme);
    themeButton.textContent = `Theme: ${theme}`;
  };
  try {
    const stored = localStorage.getItem('architecture-theme');
    if (themes.includes(stored)) theme = stored;
  } catch (_) { /* Browser privacy settings can deny offline storage. */ }
  applyTheme();
  themeButton.addEventListener('click', () => {
    theme = themes[(themes.indexOf(theme) + 1) % themes.length];
    applyTheme();
    try { localStorage.setItem('architecture-theme', theme); } catch (_) {}
  });
  const search = document.getElementById('search');
  const status = document.getElementById('search-status');
  const sections = [...document.querySelectorAll('main > section')];
  const previousOpen = new Map();
  search.addEventListener('input', () => {
    const query = search.value.trim().toLowerCase();
    let matches = 0;
    sections.forEach(section => {
      const found = !query || section.textContent.toLowerCase().includes(query);
      section.classList.toggle('hidden', !found);
      if (found) matches += 1;
      section.querySelectorAll('details.document').forEach(document => {
        if (query) {
          if (!previousOpen.has(document)) previousOpen.set(document, document.open);
          document.open = document.textContent.toLowerCase().includes(query);
        } else if (previousOpen.has(document)) {
          document.open = previousOpen.get(document);
          previousOpen.delete(document);
        }
      });
    });
    status.textContent = query ? `${matches} matching sections` : '';
  });
  const printOpen = new Map();
  window.addEventListener('beforeprint', () => {
    document.querySelectorAll('details').forEach(document => {
      printOpen.set(document, document.open);
      document.open = true;
    });
  });
  window.addEventListener('afterprint', () => {
    printOpen.forEach((open, document) => { document.open = open; });
    printOpen.clear();
  });
})();
