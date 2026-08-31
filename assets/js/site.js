(function () {
  var button = document.querySelector('.theme-toggle');
  if (!button) return;

  button.addEventListener('click', function () {
    var current = document.documentElement.dataset.theme;
    var next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    localStorage.setItem('theme', next);
  });

  document.querySelectorAll('.expand-button').forEach(function (expandButton) {
    expandButton.addEventListener('click', function () {
      var target = document.getElementById(expandButton.getAttribute('aria-controls'));
      if (!target) return;

      var expanded = expandButton.getAttribute('aria-expanded') === 'true';
      target.classList.toggle('is-collapsed', expanded);
      expandButton.setAttribute('aria-expanded', String(!expanded));
      expandButton.textContent = expanded ? 'Show all ' + expandButton.dataset.count : 'Show fewer';
    });
  });
})();
