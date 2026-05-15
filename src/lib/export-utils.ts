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
