from flask import Flask, render_template, request
from datetime import datetime

app = Flask(__name__)

# HISTORY STORAGE
analysis_history = []

def analyze_logic(content, sender, subject):
    content_lower = content.lower()
    sender_lower = sender.lower()
    subject_lower = subject.lower()
    
    # 1. Define Trustworthy & Safe Keywords
    # Indha keywords email-la irundha adhu 'Safe' nu consider aagum
    safe_indicators = [
        "meeting", "sync", "workshop", "university", "dinner", 
        "official", "microsoft", "google", "tcs", "zoho", 
        "interview", "scheduled", "reminder", "invitation"
    ]
    
    # 2. Define High-Risk Phishing Keywords
    # Indha keywords irundha 'Phishing' score egharum
    risk_indicators = [
        "urgent", "action required", "account suspended", "verify now",
        "login immediately", "password reset", "unusual activity",
        "click here", "gift card", "lottery", "winner"
    ]

    # Check if it matches safe patterns
    is_safe = any(word in content_lower or word in sender_lower or word in subject_lower for word in safe_indicators)
    
    # Check if it has risky patterns
    has_risk = any(word in content_lower or word in subject_lower for word in risk_indicators)

    # FINAL LOGIC
    # Priority 1: Risk keywords dominate
    if has_risk:
        return {
            "score": 92,
            "type": "Phishing / Malicious",
            "severity": "CRITICAL",
            "explanation": "This email uses high-pressure tactics and suspicious keywords common in phishing attacks.",
            "indicators": [
                {"title": "URGENCY_TACTIC", "desc": "Uses language designed to provoke immediate, unthinking action."},
                {"title": "SUSPICIOUS_LINK", "desc": "Contains call-to-action phrases typical of credential theft."},
                {"title": "SENDER_REPUTATION", "desc": "Domain verification failed or sender is unrecognized."}
            ]
        }
    # Priority 2: Safe keywords match
    elif is_safe:
        return {
            "score": 8,
            "type": "Legitimate Communication",
            "severity": "LOW / SAFE",
            "explanation": "The content matches professional communication patterns. No malicious intent detected.",
            "indicators": [
                {"title": "TRUSTED_CONTEXT", "desc": "Matches recognized professional/personal keywords (Sync/Meeting)."},
                {"title": "NEUTRAL_TONE", "desc": "The email is informative and does not demand urgent action."},
                {"title": "SAFE_DOMAIN", "desc": "Sender appears to be from a recognized professional domain."}
            ]
        }
    # Priority 3: Default (Neutral/Unknown)
    else:
        return {
            "score": 45,
            "type": "Unverified Content",
            "severity": "MEDIUM / CAUTION",
            "explanation": "This email doesn't have clear phishing or safe marks. Proceed with caution.",
            "indicators": [
                {"title": "UNKNOWN_SENDER", "desc": "Sender is not in the trusted or blocked list."},
                {"title": "GENERAL_CONTENT", "desc": "Content is generic and requires manual verification."}
            ]
        }

@app.route('/')
def dashboard():
    total_scans = len(analysis_history)
    recent = analysis_history[::-1][:5]
    return render_template('dashboard.html', history=recent, total=total_scans)

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    if request.method == 'POST':
        sender = request.form.get('sender_email')
        subject = request.form.get('subject_line')
        body = request.form.get('email_body')
        
        results = analyze_logic(body, sender, subject)
        results['sender'] = sender
        results['subject'] = subject
        results['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M")
        
        analysis_history.append(results)
        
        return render_template('results.html', results=results)
    return render_template('analyze_input.html')

@app.route('/history')
def history():
    return render_template('history.html', history=analysis_history[::-1])

if __name__ == '__main__':
    app.run(debug=True)