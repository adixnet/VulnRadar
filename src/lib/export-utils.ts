import { ScanResult } from './scanner-data';
import { jsPDF } from 'jspdf';
import html2canvas from 'html2canvas';

export const exportToJson = (result: ScanResult) => {
  const dataStr = JSON.stringify(result, null, 2);
  const blob = new Blob([dataStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `vulnradar-report-${result.target.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

export const exportToCsv = (result: ScanResult) => {
  if (result.vulnerabilities.length === 0) {
    const blob = new Blob(['No vulnerabilities found'], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnradar-report-${result.target.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.csv`;
    a.click();
    return;
  }

  const headers = ['Title', 'Severity', 'CVSS', 'Category', 'CWE', 'Description', 'Impact', 'Remediation'];
  const rows = result.vulnerabilities.map(v => [
    `"${v.title.replace(/"/g, '""')}"`,
    v.severity,
    v.cvss,
    `"${v.category.replace(/"/g, '""')}"`,
    v.cwe,
    `"${v.description.replace(/"/g, '""')}"`,
    `"${v.impact.replace(/"/g, '""')}"`,
    `"${v.remediation.replace(/"/g, '""')}"`
  ]);

  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.join(','))
  ].join('\n');

  const blob = new Blob([csvContent], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `vulnradar-report-${result.target.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

export const exportToPdf = async (result: ScanResult, elementId: string) => {
  const element = document.getElementById(elementId);
  if (!element) return;
  
  try {
    const canvas = await html2canvas(element, { 
      scale: 2,
      backgroundColor: '#0a0a0a', // Matches background-dark
      logging: false,
      useCORS: true
    });
    
    const imgData = canvas.toDataURL('image/jpeg', 1.0);
    const pdf = new jsPDF('p', 'mm', 'a4');
    const pdfWidth = pdf.internal.pageSize.getWidth();
    const pdfHeight = (canvas.height * pdfWidth) / canvas.width;
    
    pdf.addImage(imgData, 'JPEG', 0, 0, pdfWidth, pdfHeight);
    pdf.save(`vulnradar-report-${result.target.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.pdf`);
  } catch (error) {
    console.error('Failed to export PDF:', error);
  }
};

export const exportToMarkdown = (result: ScanResult) => {
  const mdContent = [
    `# VulnRadar Scan Report: ${result.target}`,
    `**Scan Time**: ${result.startTime.toLocaleString()}`,
    `**SSL Grade**: ${result.sslInfo.grade}`,
    ``,
    `## Vulnerabilities (${result.vulnerabilities.length})`,
    ...result.vulnerabilities.map(v => [
      `### ${v.title}`,
      `- **Severity**: ${v.severity}`,
      `- **CVSS**: ${v.cvss}`,
      `- **Category**: ${v.category}`,
      `- **CWE**: ${v.cwe}`,
      ``,
      `**Description**: ${v.description}`,
      ``,
      `**Impact**: ${v.impact}`,
      ``,
      `**Remediation**: ${v.remediation}`,
      `---`
    ].join('\n')),
  ].join('\n');

  const blob = new Blob([mdContent], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `vulnradar-report-${result.target.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

export const exportToXml = (result: ScanResult) => {
  const escapeXml = (unsafe: string) => {
    return unsafe.replace(/[<>&'"]/g, (c) => {
      switch (c) {
        case '<': return '&lt;';
        case '>': return '&gt;';
        case '&': return '&amp;';
        case '\'': return '&apos;';
        case '"': return '&quot;';
        default: return c;
      }
    });
  };

  const xmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<scanReport>
  <target>${escapeXml(result.target)}</target>
  <startTime>${result.startTime.toISOString()}</startTime>
  <sslGrade>${escapeXml(result.sslInfo.grade)}</sslGrade>
  <vulnerabilities>
${result.vulnerabilities.map(v => `    <vulnerability>
      <title>${escapeXml(v.title)}</title>
      <severity>${escapeXml(v.severity)}</severity>
      <cvss>${v.cvss}</cvss>
      <category>${escapeXml(v.category)}</category>
      <cwe>${escapeXml(v.cwe || '')}</cwe>
      <description>${escapeXml(v.description)}</description>
      <impact>${escapeXml(v.impact)}</impact>
      <remediation>${escapeXml(v.remediation)}</remediation>
    </vulnerability>`).join('\n')}
  </vulnerabilities>
</scanReport>`;

  const blob = new Blob([xmlContent], { type: 'application/xml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `vulnradar-report-${result.target.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.xml`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};
