document.addEventListener('DOMContentLoaded', () => {
    // 1. Manejo seguro de confirmación de eliminación (sin inline JS)
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

    // 2. Buscador y Paginación en tiempo real
    const filas = Array.from(document.querySelectorAll('.fila-dato'));
    const buscador = document.getElementById('buscador');
    const infoPaginacion = document.getElementById('info-paginacion');
    const contenedorBotones = document.getElementById('botones-paginacion');

    if (!buscador || !infoPaginacion || !contenedorBotones) return;

    const filasPorPagina = 5;
    let paginaActual = 1;
    let filasFiltradas = [...filas];

    function renderizar() {
        filas.forEach(f => f.style.display = 'none');

        const total = filasFiltradas.length;
        const totalPaginas = Math.ceil(total / filasPorPagina) || 1;

        if (paginaActual > totalPaginas) paginaActual = 1;

        const inicio = (paginaActual - 1) * filasPorPagina;
        const fin = inicio + filasPorPagina;

        filasFiltradas.slice(inicio, fin).forEach(f => f.style.display = '');

        if (total === 0) {
            infoPaginacion.textContent = 'No se encontraron resultados';
        } else {
            const desde = inicio + 1;
            const hasta = Math.min(fin, total);
            infoPaginacion.textContent = `Mostrando ${desde} a ${hasta} de ${total} registros`;
        }

        contenedorBotones.innerHTML = '';

        if (totalPaginas > 1) {
            const btnPrev = document.createElement('button');
            btnPrev.type = 'button';
            btnPrev.textContent = '«';
            btnPrev.className = 'btn-page';
            btnPrev.disabled = paginaActual === 1;
            btnPrev.onclick = () => { paginaActual--; renderizar(); };
            contenedorBotones.appendChild(btnPrev);

            for (let i = 1; i <= totalPaginas; i++) {
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.textContent = i;
                btn.className = `btn-page ${i === paginaActual ? 'active' : ''}`;
                btn.onclick = () => { paginaActual = i; renderizar(); };
                contenedorBotones.appendChild(btn);
            }

            const btnNext = document.createElement('button');
            btnNext.type = 'button';
            btnNext.textContent = '»';
            btnNext.className = 'btn-page';
            btnNext.disabled = paginaActual === totalPaginas;
            btnNext.onclick = () => { paginaActual++; renderizar(); };
            contenedorBotones.appendChild(btnNext);
        }
    }

    buscador.addEventListener('input', (e) => {
        const termino = e.target.value.toLowerCase().trim();

        filasFiltradas = filas.filter(fila => {
            const textoFila = Array.from(fila.querySelectorAll('td, input, select'))
                .map(el => el.value !== undefined ? el.value : el.textContent)
                .join(' ')
                .toLowerCase();
            return textoFila.includes(termino);
        });

        paginaActual = 1;
        renderizar();
    });

    renderizar();
});