import { LogEntry, SystemMetrics, TargetConfig } from '../types';

export const generatePdfReport = (logs: LogEntry[], metrics: SystemMetrics[], config: TargetConfig) => {
  void (async () => {
    const { jsPDF } = await import("jspdf");
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();

    // Header
    doc.setFillColor(15, 23, 42); // Cyber-900
    doc.rect(0, 0, pageWidth, 40, 'F');
    
    doc.setTextColor(16, 185, 129); // Emerald-500
    doc.setFontSize(22);
    doc.text("CERBERUS", 20, 20);
    
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(12);
    doc.text("REPORTE DE PENETRACIÓN & EVASIÓN", 20, 30);
    doc.text(`Fecha: ${new Date().toLocaleDateString()}`, pageWidth - 60, 30);

    // Config Section
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(14);
    doc.text("1. Configuración del Objetivo", 20, 50);
    
    doc.setFontSize(10);
    doc.setTextColor(80, 80, 80);
    doc.text(`Objetivo: ${config.url}`, 25, 60);
    doc.text(`Perfil: ${config.profile}`, 25, 66);
    doc.text(`Modo Evasión: ${config.useSmartEvasion ? 'ACTIVO' : 'INACTIVO'}`, 25, 72);

    // Metrics Section
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(14);
    doc.text("2. Métricas de Rendimiento", 20, 85);

    const avgEvasion = metrics.reduce((acc, curr) => acc + curr.evasionRate, 0) / (metrics.length || 1);
    const maxRps = Math.max(...metrics.map(m => m.requestsPerSecond), 0);
    const totalBlocks = metrics.reduce((acc, curr) => acc + curr.wafBlockCount, 0);

    doc.setFontSize(10);
    doc.setTextColor(80, 80, 80);
    doc.text(`Evasión Promedio: ${avgEvasion.toFixed(2)}%`, 25, 95);
    doc.text(`Pico RPS: ${maxRps}`, 25, 101);
    doc.text(`Total Bloqueos WAF: ${totalBlocks}`, 25, 107);

    // Logs Section (Critical Events)
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(14);
    doc.text("3. Eventos Críticos y Vulnerabilidades", 20, 120);

    let yPos = 130;
    const criticalLogs = logs.filter(l => l.level === 'ERROR' || l.level === 'SUCCESS' || l.component === 'SQLMAP').slice(-15);

    criticalLogs.forEach(log => {
      if (yPos > 270) {
        doc.addPage();
        yPos = 20;
      }
      
      let prefix = "";
      if (log.level === 'ERROR') {
        doc.setTextColor(220, 38, 38); // Red
        prefix = "[BLOQUEO]";
      } else if (log.level === 'SUCCESS') {
        doc.setTextColor(22, 163, 74); // Green
        prefix = "[ÉXITO]";
      } else {
        doc.setTextColor(80, 80, 80);
        prefix = "[INFO]";
      }

      const cleanMsg = doc.splitTextToSize(`${log.timestamp} - ${prefix} ${log.message}`, pageWidth - 40);
      doc.text(cleanMsg, 25, yPos);
      yPos += (cleanMsg.length * 5) + 2;
    });

    // Footer
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    doc.text("Generado automáticamente por el Sistema Cerberus v2.4", 20, 290);

    doc.save(`cerberus_report_${Date.now()}.pdf`);
  })().catch((error: unknown) => {
    console.error('PDF generation failed:', error);
  });
};
