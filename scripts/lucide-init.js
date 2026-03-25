function refreshLucideIcons() {
  if (window.lucide && typeof window.lucide.createIcons === 'function') {
    window.lucide.createIcons();
  }
}

window.refreshLucideIcons = refreshLucideIcons;
document.addEventListener('DOMContentLoaded', refreshLucideIcons);
