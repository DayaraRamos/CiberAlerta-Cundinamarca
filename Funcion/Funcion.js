// ── NAVEGACIÓN ──
  function cambiarPantalla(id, btn) {
    document.querySelectorAll('.pantalla').forEach(p => p.classList.remove('activa'));
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('activo'));
    document.getElementById('pantalla-' + id).classList.add('activa');
    btn.classList.add('activo');
  }

  // ══════════════════════════════════════
  // PANTALLA 1 — MENSAJES
  // ══════════════════════════════════════
  function cargar(texto) {
    document.getElementById('campo').value = texto;
    analizarMensaje();
  }

  function limpiarMensaje() {
    document.getElementById('campo').value = '';
    const res = document.getElementById('resultado-mensaje');
    res.style.display = 'none'; res.innerHTML = '';
  }

  async function analizarMensaje() {
    const texto = document.getElementById('campo').value.trim();
    if (!texto) return;
    const res = document.getElementById('resultado-mensaje');
    res.style.display = 'block';
    res.innerHTML = '<div class="cargando">🔍 Analizando mensaje...</div>';
    try {
      const response = await fetch('/analizar', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ texto })
      });
      const data = await response.json();
      mostrarResultadoMensaje(data);
    } catch (e) {
      res.innerHTML = '<div class="cargando">❌ Error al analizar. Verifica que el servidor esté corriendo.</div>';
    }
  }

  function mostrarResultadoMensaje(data) {
    const config = {
      peligroso: { bg:'#FFEBEE', borde:'#C62828', tc:'#B71C1C', emoji:'🚨',
        titulo:'¡PELIGRO! Este mensaje es una ESTAFA',
        semColor:'#EF5350', semTexto:'PELIGROSO — No respondas ni hagas clic' },
      sospechoso: { bg:'#FFF3E0', borde:'#E65100', tc:'#BF360C', emoji:'⚠️',
        titulo:'¡CUIDADO! Este mensaje es SOSPECHOSO',
        semColor:'#FFA726', semTexto:'SOSPECHOSO — Verifica antes de actuar' },
      seguro: { bg:'#E8F5E9', borde:'#2E7D32', tc:'#1B5E20', emoji:'✅',
        titulo:'Este mensaje parece SEGURO',
        semColor:'#66BB6A', semTexto:'SEGURO — No se detectaron amenazas' }
    };
    const c = config[data.nivel];
    const razones = data.razones.map(r => `<div class="item">• ${r}</div>`).join('');
    const consejos = data.consejos.slice(0,5).map(x => `<div class="item">${x}</div>`).join('');

    // Bloque VirusTotal
    let vtBloque = '';
    if (data.virustotal && !data.virustotal.error) {
      const vt = data.virustotal;
      const vtColor = vt.veredicto === 'peligroso' ? '#B71C1C'
                    : vt.veredicto === 'sospechoso' ? '#E65100' : '#2E7D32';
      const vtEmoji = vt.veredicto === 'peligroso' ? '🔴'
                    : vt.veredicto === 'sospechoso' ? '🟡' : '🟢';
      vtBloque = `
        <div class="vt-bloque" style="border-left:4px solid ${vtColor};">
          <div class="vt-titulo" style="color:${vtColor};">🔬 Verificación VirusTotal</div>
          <div class="vt-fila">${vtEmoji} Veredicto: <strong style="color:${vtColor};text-transform:uppercase;">${vt.veredicto}</strong></div>
          <div class="vt-fila">🛡️ <strong>${vt.maliciosos}</strong> de <strong>${vt.total}</strong> antivirus lo detectaron como malicioso</div>
          <div class="vt-fila">⚠️ Sospechosos: <strong>${vt.sospechosos}</strong></div>
          <div class="vt-url">🔗 ${vt.url}</div>
        </div>`;
    }

    const res = document.getElementById('resultado-mensaje');
    res.style.animation = 'none'; res.offsetHeight; res.style.animation = 'slideUp 0.35s ease both';
    res.innerHTML = `
      <div class="resultado-caja" style="background:${c.bg}; border-color:${c.borde};">
        <div class="resultado-top">
          <div class="resultado-emoji">${c.emoji}</div>
          <div>
            <div class="resultado-titulo" style="color:${c.tc}">${c.titulo}</div>
            <div class="semaforo">
              <div class="semaforo-dot" style="background:${c.semColor}"></div>
              <span style="color:${c.tc}">${c.semTexto}</span>
            </div>
          </div>
        </div>
        <div class="seccion-label" style="color:${c.tc}">${data.nivel !== 'seguro' ? '¿Por qué es peligroso?' : 'Análisis'}</div>
        ${razones}
        <div class="seccion-label" style="color:${c.tc}; margin-top:16px;">¿Qué debes hacer?</div>
        ${consejos}
        ${vtBloque}
      </div>`;
  }

  // ══════════════════════════════════════
  // PANTALLA 2 — ARCHIVOS
  // ══════════════════════════════════════
  const iconosPorExtension = {
    pdf: '📕', exe: '⚙️', zip: '🗜️', rar: '🗜️',
    docx: '📘', doc: '📘', xlsx: '📗', apk: '📱',
    jpg: '🖼️', png: '🖼️', mp4: '🎬', default: '📄'
  };

  let archivoActual = null;

  document.getElementById('inputArchivo').addEventListener('change', function(e) {
    if (e.target.files[0]) seleccionarArchivo(e.target.files[0]);
  });

  function dragOver(e) { e.preventDefault(); document.getElementById('zonaDrop').classList.add('dragover'); }
  function dragLeave(e) { document.getElementById('zonaDrop').classList.remove('dragover'); }
  function dragDrop(e) {
    e.preventDefault();
    document.getElementById('zonaDrop').classList.remove('dragover');
    if (e.dataTransfer.files[0]) seleccionarArchivo(e.dataTransfer.files[0]);
  }

  function seleccionarArchivo(file) {
    archivoActual = file;
    const ext = file.name.split('.').pop().toLowerCase();
    const icono = iconosPorExtension[ext] || iconosPorExtension.default;
    const tamano = file.size < 1024*1024
      ? (file.size/1024).toFixed(1) + ' KB'
      : (file.size/1024/1024).toFixed(1) + ' MB';

    document.getElementById('archivoIcono').textContent = icono;
    document.getElementById('archivoNombre').textContent = file.name;
    document.getElementById('archivoTamano').textContent = tamano + ' · ' + ext.toUpperCase();
    document.getElementById('archivoSeleccionado').style.display = 'flex';
    document.getElementById('zonaDrop').style.display = 'none';

    const btn = document.getElementById('btnAnalizarArchivo');
    btn.disabled = false; btn.style.opacity = '1'; btn.style.cursor = 'pointer';
    document.getElementById('resultado-archivo').style.display = 'none';
  }

  async function analizarArchivo() {
    if (!archivoActual) return;
    const progreso = document.getElementById('progresoWrap');
    const bar = document.getElementById('progresoBar');
    const label = document.getElementById('progresoLabel');
    const res = document.getElementById('resultado-archivo');

    progreso.style.display = 'block'; res.style.display = 'none';
    label.textContent = 'Enviando archivo a VirusTotal...'; bar.style.width = '0%';

    // Animación de progreso
    let pct = 0;
    const intervalo = setInterval(() => {
      pct += Math.random() * 15;
      if (pct >= 90) { pct = 90; clearInterval(intervalo); }
      bar.style.width = pct + '%';
      if (pct > 30) label.textContent = 'Analizando con 70+ motores antivirus...';
      if (pct > 60) label.textContent = 'Recopilando resultados...';
    }, 300);

    try {
      const formData = new FormData();
      formData.append('archivo', archivoActual);
      const response = await fetch('/analizar-archivo', { method: 'POST', body: formData });
      const data = await response.json();
      clearInterval(intervalo);
      bar.style.width = '100%';
      label.textContent = '✅ Análisis completado';
      setTimeout(() => {
        progreso.style.display = 'none';
        mostrarResultadoArchivo(data);
      }, 500);
    } catch(e) {
      clearInterval(intervalo);
      progreso.style.display = 'none';
      res.style.display = 'block';
      res.style.background = '#FFEBEE'; res.style.borderColor = '#C62828';
      res.innerHTML = '<div style="color:#B71C1C; font-weight:700; padding:10px;">❌ Error al analizar. Verifica que el servidor esté corriendo.</div>';
    }
  }

  function mostrarResultadoArchivo(data) {
    const res = document.getElementById('resultado-archivo');
    const vt = data.virustotal;
    if (!vt || vt.error) {
      res.style.display = 'block'; res.style.background = '#FFF3E0'; res.style.borderColor = '#E65100';
      res.innerHTML = `<div style="color:#E65100; font-weight:700; padding:10px;">⚠️ ${vt?.error || 'No se pudo analizar el archivo'}</div>`;
      return;
    }
    const esPeligroso = vt.maliciosos >= 3;
    const esSospechoso = vt.maliciosos >= 1 || vt.sospechosos >= 2;
    const bg = esPeligroso ? '#FFEBEE' : esSospechoso ? '#FFF3E0' : '#E8F5E9';
    const borde = esPeligroso ? '#C62828' : esSospechoso ? '#E65100' : '#2E7D32';
    const tc = esPeligroso ? '#B71C1C' : esSospechoso ? '#BF360C' : '#1B5E20';
    const emoji = esPeligroso ? '🚨' : esSospechoso ? '⚠️' : '✅';
    const titulo = esPeligroso ? '¡ARCHIVO PELIGROSO! No lo abras.' : esSospechoso ? '¡ARCHIVO SOSPECHOSO! Procede con cuidado.' : 'Archivo parece LIMPIO';

    res.style.display = 'block'; res.style.background = bg; res.style.borderColor = borde;
    res.innerHTML = `
      <div class="resultado-archivo-top">
        <div style="font-size:40px;">${emoji}</div>
        <div>
          <div style="font-size:17px; font-weight:900; color:${tc};">${titulo}</div>
          <div class="semaforo" style="margin-top:8px;">
            <div class="semaforo-dot" style="background:${borde}"></div>
            <span style="color:${tc}; font-size:12px;">${vt.veredicto?.toUpperCase()} — Análisis VirusTotal</span>
          </div>
        </div>
      </div>
      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-numero" style="color:#B71C1C;">${vt.maliciosos}</div>
          <div class="stat-label">Detecciones maliciosas</div>
        </div>
        <div class="stat-card">
          <div class="stat-numero" style="color:#E65100;">${vt.sospechosos}</div>
          <div class="stat-label">Sospechosos</div>
        </div>
        <div class="stat-card">
          <div class="stat-numero" style="color:#2E7D32;">${vt.total - vt.maliciosos - vt.sospechosos}</div>
          <div class="stat-label">Sin amenazas</div>
        </div>
        <div class="stat-card">
          <div class="stat-numero" style="color:#1565C0;">${vt.total}</div>
          <div class="stat-label">Total antivirus</div>
        </div>
      </div>`;
  }

  function limpiarArchivo() {
    archivoActual = null;
    document.getElementById('zonaDrop').style.display = 'block';
    document.getElementById('archivoSeleccionado').style.display = 'none';
    document.getElementById('progresoWrap').style.display = 'none';
    document.getElementById('resultado-archivo').style.display = 'none';
    document.getElementById('inputArchivo').value = '';
    const btn = document.getElementById('btnAnalizarArchivo');
    btn.disabled = true; btn.style.opacity = '0.5'; btn.style.cursor = 'not-allowed';
  }