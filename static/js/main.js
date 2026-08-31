document.addEventListener('DOMContentLoaded', () => {
    const deleteButtons = document.querySelectorAll('.btn-eliminar-confirm');
    deleteButtons.forEach(button => {
        button.addEventListener('click', (event) => {
            const nombre = button.getAttribute('data-nombre') || 'este registro';
            const confirmacion = confirm(`¿Estás seguro de que deseas eliminar al usuario "${nombre}"?`);
            if (!confirmacion) {
                event.preventDefault();
            }
        });
    });
});