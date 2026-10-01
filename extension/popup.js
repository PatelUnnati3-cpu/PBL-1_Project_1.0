function checkURL() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) {
    alert('Please enter a URL!');
    return;
  }

  const loading = document.getElementById('loading');
  const result = document.getElementById('result');
  
  loading.style.display = 'block';
  result.style.display = 'none';

  fetch('http://127.0.0.1:5000/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url })
  })
  .then(response => response.json())
  .then(data => {
    loading.style.display = 'none';
    
    const resultDiv = document.getElementById('result');
    const verdict = document.getElementById('verdict');
    const score = document.getElementById('score');
    const riskFill = document.getElementById('riskFill');
    const reasons = document.getElementById('reasons');

    resultDiv.className = 'result';
    if (data.verdict === 'PHISHING') {
      resultDiv.classList.add('phishing');
      verdict.textContent = '🚨 PHISHING DETECTED';
    } else if (data.verdict === 'SUSPICIOUS') {
      resultDiv.classList.add('suspicious');
      verdict.textContent = '⚠️ SUSPICIOUS URL';
    } else {
      resultDiv.classList.add('safe');
      verdict.textContent = '✅ SAFE URL';
    }

    score.textContent = `Risk Score: ${data.risk_score}%`;
    riskFill.style.width = `${data.risk_score}%`;

    if (data.reasons && data.reasons.length > 0) {
      reasons.innerHTML = '<strong>Why flagged:</strong><ul>' +
        data.reasons.map(r => `<li>${r}</li>`).join('') +
        '</ul>';
    } else {
      reasons.innerHTML = '<strong>No suspicious patterns found.</strong>';
    }

    resultDiv.style.display = 'block';
  })
  .catch(error => {
    loading.style.display = 'none';
    alert('Error: Make sure Flask server is running on port 5000!');
  });
}

// Auto-fill current tab URL
chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
  if (tabs[0]) {
    document.getElementById('urlInput').value = tabs[0].url;
  }
});
document.getElementById('checkBtn').addEventListener('click', checkURL);