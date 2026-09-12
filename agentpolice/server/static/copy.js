'use strict';

/* Copy buttons for `.cmd[data-copy]` blocks.
   Added in JS rather than markup so the copied text is exactly what the page
   shows, and so a page with JS disabled still renders a readable command
   block instead of a button that does nothing. */

(function () {
  const EN = document.documentElement.lang.startsWith('en');
  const LABEL = EN ? 'Copy' : '复制';
  const DONE = EN ? 'Copied' : '已复制';
  const FAIL = EN ? 'Select and copy' : '请手动选中复制';

  for (const block of document.querySelectorAll('.cmd[data-copy]')) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy';
    btn.textContent = LABEL;
    btn.setAttribute('aria-label', LABEL);

    btn.addEventListener('click', async () => {
      // The button lives inside the block, so its own label would otherwise
      // end up in the clipboard.
      const text = Array.from(block.childNodes)
        .filter((n) => n !== btn)
        .map((n) => n.textContent)
        .join('')
        .trim();
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = DONE;
        btn.classList.add('done');
      } catch (_) {
        // Clipboard access is refused on insecure origins and in some
        // embedded browsers; say so rather than silently doing nothing.
        btn.textContent = FAIL;
      }
      setTimeout(() => {
        btn.textContent = LABEL;
        btn.classList.remove('done');
      }, 1800);
    });

    block.appendChild(btn);
  }
})();
