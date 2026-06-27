// Small helper script for intern-friendly UX.
// It highlights JSON fields with a quick validity check before submit.

document.addEventListener('DOMContentLoaded', () => {
  const forms = document.querySelectorAll('form');

  forms.forEach((form) => {
    form.addEventListener('submit', () => {
      const jsonAreas = form.querySelectorAll('textarea[name="headers"], textarea[name="params"], textarea[name="json_body"]');
      jsonAreas.forEach((area) => {
        const text = area.value.trim();
        if (!text) return;
        try {
          JSON.parse(text);
          area.style.outline = '2px solid #198754';
        } catch (err) {
          // We do not block submit here because server-side validation is the final source of truth.
          area.style.outline = '2px solid #dc3545';
        }
      });
    });
  });
});
