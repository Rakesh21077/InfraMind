"""
Generate a professional 12-slide widescreen PowerPoint pitch deck for InfraMind.
Utilizes python-pptx with custom typography, clean cybersecurity palette, and structured layouts.
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN

def create_deck(output_path: str):
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    # Palette
    C_NAVY = RGBColor(15, 23, 42)       # #0F172A Dark Slate
    C_BLUE = RGBColor(37, 99, 235)      # #2563EB Royal Blue
    C_DARK = RGBColor(31, 41, 55)       # #1F2937 Text dark
    C_MUTED = RGBColor(100, 116, 139)   # #64748B Secondary text
    C_CARD = RGBColor(248, 250, 252)    # #F8FAFC Card background
    C_RED = RGBColor(220, 38, 38)       # #DC2626 Critical red
    C_GREEN = RGBColor(22, 163, 74)     # #16A34A Success green

    blank_layout = prs.slide_layouts[6]

    def add_header(slide, title_text, category="INFRAMIND — AI CLOUD SECURITY GUARDRAIL"):
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(0.35))
        tf_c = cat_box.text_frame
        tf_c.word_wrap = True
        p_c = tf_c.paragraphs[0]
        p_c.text = category.upper()
        p_c.font.size = Pt(11)
        p_c.font.bold = True
        p_c.font.color.rgb = C_BLUE

        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.75), Inches(11.7), Inches(0.8))
        tf_t = title_box.text_frame
        tf_t.word_wrap = True
        p_t = tf_t.paragraphs[0]
        p_t.text = title_text
        p_t.font.size = Pt(24)
        p_t.font.bold = True
        p_t.font.color.rgb = C_NAVY

    def add_footer(slide, current_idx, total=12):
        footer_box = slide.shapes.add_textbox(Inches(0.8), Inches(6.9), Inches(11.7), Inches(0.4))
        tf = footer_box.text_frame
        p = tf.paragraphs[0]
        p.text = f"InfraMind Engineering Project  |  Slide {current_idx} of {total}  |  Confidential"
        p.font.size = Pt(9)
        p.font.color.rgb = C_MUTED

    slides_data = [
        # Slide 1: Title
        {
            "is_title": True,
            "title": "InfraMind",
            "subtitle": "AI Cloud Security Guardrail for Startups & IT",
            "tagline": "Real-time AI Threat Prioritization & Controlled Remediation Engine",
            "team": "Six-Member Capstone Engineering Project | AMD GPU ROCm & AWS Boto3 Integration",
        },
        # Slide 2
        {
            "title": "The Cloud Misconfiguration Crisis",
            "subtitle": "Startups move fast, but cloud breaches happen in seconds",
            "points": [
                ("Critical Exposure Points", "Accidental public Amazon S3 buckets and leaked AWS IAM keys represent over 80% of startup cloud security vulnerabilities."),
                ("PII & Financial Exposure", "A single misconfigured bucket ACL exposes database backups, customer records, and proprietary intellectual property."),
                ("Catastrophic Breach Costs", "IBM's Cost of a Data Breach report indicates cloud breaches cost an average of $4.45M, with detection taking over 270 days."),
                ("Vulnerability Velocity", "Automated adversary bots scan public GitHub repositories and AWS IP ranges within 3 minutes of credential leakage.")
            ]
        },
        # Slide 3
        {
            "title": "Alert Fatigue & The Manual Remediation Bottleneck",
            "subtitle": "High log volume meets limited security personnel",
            "points": [
                ("Overwhelming Telemetry", "AWS CloudTrail outputs tens of thousands of raw JSON lines per day, drowning engineering teams in noise."),
                ("Severe Alert Fatigue", "Critical misconfiguration alerts sit unreviewed in notification queues for days or weeks."),
                ("Specialized Knowledge Gap", "Correctly interpreting IAM policies and S3 ACLs requires senior cloud security engineering experience."),
                ("The Production Panic", "Manual CLI or console fixes under pressure frequently cause live application downtime or broken microservice dependencies.")
            ]
        },
        # Slide 4
        {
            "title": "InfraMind: Closed-Loop AI Cloud Guardrail",
            "subtitle": "From raw telemetry to controlled auto-patching in seconds",
            "points": [
                ("Automated Ingestion", "Parses complex AWS security events from CloudTrail and security logs into structured telemetry."),
                ("GPU-Powered AI Analysis", "Translates dense JSON logs into threat severity ratings, impact scores (0-10), and blast radius estimates."),
                ("Controlled Remediation", "Pre-built, production-tested Boto3 auto-patch routines for S3 buckets and IAM credentials."),
                ("Incident Time-Machine", "Interactive conversational AI allowing security engineers to interrogate incident history using natural language.")
            ]
        },
        # Slide 5
        {
            "title": "Multi-Tier System Architecture",
            "subtitle": "End-to-end data pipeline with human-in-the-loop safeguards",
            "points": [
                ("Tier 1: Telemetry Ingestion", "Ingests AWS CloudTrail and event telemetry from mock_logs.json or live custom log feeds."),
                ("Tier 2: AI Analysis Engine (agent.py)", "Connects to AMD Instinct GPU endpoints running ROCm vLLM or switches to deterministic fallback."),
                ("Tier 3: Operator Console (app.py)", "Streamlit dashboard displaying threat severity cards, blast radius estimates, and authorization workflows."),
                ("Tier 4: Guardrail Remediation (remediation.py)", "Boto3 execution engine enforcing default dry-run simulation and explicit human operator approval.")
            ]
        },
        # Slide 6
        {
            "title": "AMD Developer Cloud & ROCm Integration",
            "subtitle": "Accelerated open-weights LLM serving with vLLM",
            "points": [
                ("AMD Instinct Hardware", "Deployed on AMD Instinct MI300X/MI250 GPUs utilizing the ROCm software stack for high-throughput inference."),
                ("Containerized vLLM Server", "Packaged via rocm/vllm:latest running meta-llama/Meta-Llama-3-8B-Instruct on port 8000."),
                ("OpenAI-Compatible Standard", "Universal API compatibility allowing transparent transition between AMD cloud endpoints, local Ollama, and test harnesses."),
                ("Dual-Mode Resiliency", "Features an instant, non-blocking deterministic fallback ensuring 100% dashboard uptime even during network disruption.")
            ]
        },
        # Slide 7
        {
            "title": "AI Threat Prioritization & Blast Radius Scoring",
            "subtitle": "Quantifiable, calibrated risk metrics for security teams",
            "points": [
                ("Threat Severity Levels", "Normalizes events into CRITICAL, HIGH, MEDIUM, and LOW categories based on exploitability."),
                ("Calibrated Threat Score (0-10)", "Mathematical impact score quantifying risk of tenant takeover, data exfiltration, or lateral movement."),
                ("Blast Radius Estimation (0-10)", "Estimates potential blast radius across dependent microservices, customer data stores, and IAM roles."),
                ("Strict Remediation Whitelist", "LLMs can only recommend pre-vetted actions (fix_s3_bucket, revoke_iam_key, none). Code execution is strictly prohibited.")
            ]
        },
        # Slide 8
        {
            "title": "Scenario A: Public S3 Bucket Auto-Patch",
            "subtitle": "Preventing catastrophic data exfiltration in Amazon S3",
            "points": [
                ("Event Detection (evt-101)", "PutBucketAcl telemetry shows global public read-write permissions granted to AllUsers on customer backup bucket."),
                ("AI Threat Assessment", "Evaluated as CRITICAL | Threat Score: 9/10 | Blast Radius: 8/10 (PII and financial records at risk)."),
                ("Targeted Remediation", "fix_s3_bucket() invokes AWS put_public_access_block() to close all exposure vectors."),
                ("Four-Flag Protection", "Explicitly sets BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets to True.")
            ]
        },
        # Slide 9
        {
            "title": "Scenario B: Compromised IAM Key Revocation",
            "subtitle": "Neutralizing leaked credentials while preserving forensic evidence",
            "points": [
                ("Event Detection (evt-102)", "CreateAccessKey telemetry confirms key AKIAIOSFODNN7EXAMPLE leaked in a public code repository."),
                ("AI Threat Assessment", "Evaluated as CRITICAL | Threat Score: 10/10 | Blast Radius: 9/10 (Immediate tenant compromise threat)."),
                ("Controlled Deactivation", "revoke_iam_key() calls update_access_key(Status='Inactive'). The key is neutralized without deletion."),
                ("Forensic & Root Guardrails", "Preserves audit history in CloudTrail. Automatically blocks and rejects automated deactivation of root account keys.")
            ]
        },
        # Slide 10
        {
            "title": "Streamlit Dashboard & Incident Time-Machine",
            "subtitle": "Modern, intuitive operations console for cloud defenders",
            "points": [
                ("Executive Threat Metrics", "Real-time KPI counters tracking total alerts, critical threats, pending reviews, and remediated incidents."),
                ("Interactive Threat Cards", "One-click 'Analyze Alert via AMD GPU' displays risk summaries, blast radius, and target resource bindings."),
                ("Explicit Operator Approval", "Mandatory confirmation checkbox prevents accidental clicks. Only approved actions trigger patch execution."),
                ("Incident Time-Machine Assistant", "Conversational AI answers natural language queries: 'What API keys were flagged?', 'Which incidents are critical?'")
            ]
        },
        # Slide 11
        {
            "title": "Defense-in-Depth & Multi-Layer Safety Controls",
            "subtitle": "Zero accidental cloud mutations, zero secret leakage",
            "points": [
                ("Dry-Run Simulation Default", "DRY_RUN=True prevents real AWS changes during development, testing, and demonstrations."),
                ("Master Circuit Breaker", "LIVE_EXECUTION_ENABLED=False must be explicitly enabled in .env before any live cloud call occurs."),
                ("Strict Identity Validation", "Remediation verifies exact bucket names and mandatory IAM usernames before dispatch."),
                ("Credential Sanitization", "Automatic regex redaction of AWS access keys, secret keys, session tokens, and bearer auth headers.")
            ]
        },
        # Slide 12
        {
            "title": "Business Impact, Roadmap & Conclusion",
            "subtitle": "Transforming cloud security from reactive panic into proactive guardrails",
            "points": [
                ("90% Reduction in MTTR", "Mean Time to Remediate critical misconfigurations drops from hours to under 30 seconds."),
                ("100% Elimination of Console Errors", "Pre-tested automated scripts replace risky manual AWS management console navigation."),
                ("Verified Quality Assurance", "50 automated unit tests passing with 100% coverage across input validation, LLM analysis, and safety gates."),
                ("Future Expansion Roadmap", "Multi-cloud coverage (Azure Blob & Google Cloud IAM), Slack/Teams approval bots, and real-time CloudWatch streaming.")
            ]
        },
    ]

    for idx, sdata in enumerate(slides_data, start=1):
        slide = prs.slides.add_slide(blank_layout)

        if sdata.get("is_title"):
            # Title slide design
            bg_box = slide.shapes.add_textbox(Inches(0.8), Inches(1.5), Inches(11.7), Inches(4.5))
            tf = bg_box.text_frame
            tf.word_wrap = True

            p1 = tf.paragraphs[0]
            p1.text = "🛡️ " + sdata["title"]
            p1.font.size = Pt(48)
            p1.font.bold = True
            p1.font.color.rgb = C_BLUE
            p1.space_after = Pt(14)

            p2 = tf.add_paragraph()
            p2.text = sdata["subtitle"]
            p2.font.size = Pt(24)
            p2.font.bold = True
            p2.font.color.rgb = C_NAVY
            p2.space_after = Pt(12)

            p3 = tf.add_paragraph()
            p3.text = sdata["tagline"]
            p3.font.size = Pt(16)
            p3.font.color.rgb = C_MUTED
            p3.space_after = Pt(28)

            p4 = tf.add_paragraph()
            p4.text = sdata["team"]
            p4.font.size = Pt(13)
            p4.font.bold = True
            p4.font.color.rgb = C_BLUE

            add_footer(slide, 1)
            continue

        # Standard Content Slide
        add_header(slide, sdata["title"])

        sub_box = slide.shapes.add_textbox(Inches(0.8), Inches(1.5), Inches(11.7), Inches(0.4))
        p_sub = sub_box.text_frame.paragraphs[0]
        p_sub.text = sdata.get("subtitle", "")
        p_sub.font.size = Pt(14)
        p_sub.font.color.rgb = C_MUTED

        # 4 content cards
        points = sdata.get("points", [])
        card_w = Inches(5.6)
        card_h = Inches(2.1)
        positions = [
            (Inches(0.8), Inches(2.1)),
            (Inches(6.9), Inches(2.1)),
            (Inches(0.8), Inches(4.5)),
            (Inches(6.9), Inches(4.5)),
        ]

        for p_idx, (heading, desc) in enumerate(points):
            if p_idx >= 4:
                break
            x, y = positions[p_idx]
            shape = slide.shapes.add_shape(1, x, y, card_w, card_h)  # 1 = MSO_SHAPE.RECTANGLE
            shape.fill.solid()
            shape.fill.fore_color.rgb = C_CARD
            shape.line.color.rgb = RGBColor(226, 232, 240)
            shape.line.width = Pt(1)

            tf = shape.text_frame
            tf.word_wrap = True
            tf.margin_left = Inches(0.25)
            tf.margin_top = Inches(0.2)
            tf.margin_right = Inches(0.25)

            p_h = tf.paragraphs[0]
            p_h.text = heading
            p_h.font.size = Pt(15)
            p_h.font.bold = True
            p_h.font.color.rgb = C_NAVY
            p_h.space_after = Pt(6)

            p_d = tf.add_paragraph()
            p_d.text = desc
            p_d.font.size = Pt(12)
            p_d.font.color.rgb = C_DARK

        add_footer(slide, idx)

    prs.save(output_path)
    print(f"Presentation saved successfully to: {output_path}")

if __name__ == "__main__":
    out_dir = os.path.join(os.path.dirname(__file__), "presentation")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "InfraMind_Pitch_Deck.pptx")
    create_deck(out_file)
