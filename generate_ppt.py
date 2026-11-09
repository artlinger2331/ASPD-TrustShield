import os
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

def create_deck(output_path: str):
    prs = Presentation()
    # 16:9 Widescreen
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Color Palette (Cyber / SOC Dark Theme)
    BG_DARK = RGBColor(10, 15, 29)       # #0A0F1D
    CARD_BG = RGBColor(30, 41, 59)       # #1E293B
    CARD_BORDER = RGBColor(51, 65, 85)   # #334155
    CYAN = RGBColor(14, 165, 233)        # #0EA5E9
    BLUE = RGBColor(59, 130, 246)        # #3B82F6
    WHITE = RGBColor(248, 250, 252)      # #F8FAFC
    SLATE = RGBColor(148, 163, 184)      # #94A3B8
    RED = RGBColor(239, 68, 68)          # #EF4444
    GREEN = RGBColor(16, 185, 129)       # #10B981
    AMBER = RGBColor(245, 158, 11)       # #F59E0B

    def set_slide_background(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_DARK
        bg.line.fill.background()
        return bg

    def add_header(slide, title_text, category="TRUSTSHIELD PLATFORM"):
        # Category / Overline
        tb_cat = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.5), Inches(0.35))
        tf_cat = tb_cat.text_frame
        tf_cat.word_wrap = True
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = category.upper()
        p_cat.font.size = Pt(11)
        p_cat.font.bold = True
        p_cat.font.color.rgb = CYAN
        p_cat.font.name = "Calibri"

        # Main Title
        tb_title = slide.shapes.add_textbox(Inches(0.8), Inches(0.75), Inches(11.5), Inches(0.6))
        tf_title = tb_title.text_frame
        tf_title.word_wrap = True
        p_title = tf_title.paragraphs[0]
        p_title.text = title_text
        p_title.font.size = Pt(24)
        p_title.font.bold = True
        p_title.font.color.rgb = WHITE
        p_title.font.name = "Calibri"

    def add_card(slide, left, top, width, height, bg_color=CARD_BG, border_color=CARD_BORDER):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height))
        card.fill.solid()
        card.fill.fore_color.rgb = bg_color
        card.line.color.rgb = border_color
        card.line.width = Pt(1)
        return card

    # =========================================================================
    # SLIDE 1: Title Slide (Cover)
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    # Decorative glow card behind title
    add_card(s1, 1.2, 1.2, 10.933, 5.1, bg_color=RGBColor(15, 23, 42), border_color=CYAN)

    tb = s1.shapes.add_textbox(Inches(1.8), Inches(2.0), Inches(9.7), Inches(3.5))
    tf = tb.text_frame
    tf.word_wrap = True

    p_badge = tf.paragraphs[0]
    p_badge.text = "NEXT-GENERATION CYBER DEFENSE PLATFORM"
    p_badge.font.size = Pt(13)
    p_badge.font.bold = True
    p_badge.font.color.rgb = CYAN
    p_badge.font.name = "Calibri"

    p_main = tf.add_paragraph()
    p_main.text = "TrustShield™"
    p_main.font.size = Pt(48)
    p_main.font.bold = True
    p_main.font.color.rgb = WHITE
    p_main.font.name = "Calibri"
    p_main.space_before = Pt(8)
    p_main.space_after = Pt(8)

    p_sub = tf.add_paragraph()
    p_sub.text = "Intelligent Multi-Vector Website Trust, Phishing Defense & Threat Intelligence"
    p_sub.font.size = Pt(18)
    p_sub.font.color.rgb = RGBColor(186, 230, 253)
    p_sub.font.name = "Calibri"

    p_meta = tf.add_paragraph()
    p_meta.text = "Hackmatrix 2026 • Live Project Demonstration & Executive Overview"
    p_meta.font.size = Pt(12)
    p_meta.font.italic = True
    p_meta.font.color.rgb = SLATE
    p_meta.font.name = "Calibri"
    p_meta.space_before = Pt(28)

    # =========================================================================
    # SLIDE 2: The Critical Problem
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "The Problem: Why Traditional Blocklists Fail", "THREAT LANDSCAPE")

    cards_data_s2 = [
        ("Ephemeral Zero-Day Phishing",
         "Attacker domains stay online for under 4 hours on average. By the time static blocklists ingest the URL, credentials have already been harvested.",
         RED, "THREAT VECTOR 1"),
        ("Deceptive Brand Spoofing",
         "Adversaries exploit Punycode, homoglyphs, and subdomains (e.g., login.bank.xyz) while obtaining authentic wildcard Let's Encrypt SSL certificates.",
         AMBER, "THREAT VECTOR 2"),
        ("Silent Security Misconfiguration",
         "Over 65% of websites lack HTTP Strict Transport Security (HSTS) and Content Security Policy (CSP), leaving users vulnerable to clickjacking and MITM.",
         CYAN, "THREAT VECTOR 3")
    ]

    for idx, (title, desc, color, tag) in enumerate(cards_data_s2):
        left = 0.8 + idx * 4.0
        add_card(s2, left, 1.8, 3.7, 4.8)
        tb = s2.shapes.add_textbox(Inches(left + 0.3), Inches(2.1), Inches(3.1), Inches(4.2))
        tf = tb.text_frame
        tf.word_wrap = True

        p_tag = tf.paragraphs[0]
        p_tag.text = tag
        p_tag.font.size = Pt(10)
        p_tag.font.bold = True
        p_tag.font.color.rgb = color
        p_tag.font.name = "Calibri"

        p_head = tf.add_paragraph()
        p_head.text = title
        p_head.font.size = Pt(16)
        p_head.font.bold = True
        p_head.font.color.rgb = WHITE
        p_head.font.name = "Calibri"
        p_head.space_before = Pt(8)
        p_head.space_after = Pt(12)

        p_desc = tf.add_paragraph()
        p_desc.text = desc
        p_desc.font.size = Pt(12.5)
        p_desc.font.color.rgb = SLATE
        p_desc.font.name = "Calibri"

    # =========================================================================
    # SLIDE 3: The 7-Stage Inspection Pipeline
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "The Solution: 7-Stage Multi-Vector Inspection Pipeline", "CORE ARCHITECTURE")

    pipeline_steps = [
        ("1. URL & SSRF", "RFC canonicalization, loopback/private IP defense, Punycode detection"),
        ("2. DNS & Infra", "Authoritative NS, MX/SPF records, WHOIS domain age inspection"),
        ("3. Cryptography", "Full X.509 certificate chain validation, SAN coverage & CA trust"),
        ("4. Web Headers", "HSTS preload, CSP, X-Frame-Options (Clickjacking), X-Content-Type"),
        ("5. DOM Heuristics", "Credential harvesting forms, password fields, brand logo matching"),
        ("6. ML Classifier", "Random Forest lexical model, token entropy, domain age context"),
        ("7. Threat Intel", "Multi-engine consensus: Google Safe Browsing, URLhaus, VirusTotal")
    ]

    for idx, (step_title, step_desc) in enumerate(pipeline_steps):
        top = 1.7 + idx * 0.74
        add_card(s3, 0.8, top, 11.7, 0.65)
        tb = s3.shapes.add_textbox(Inches(1.0), Inches(top + 0.08), Inches(11.3), Inches(0.5))
        tf = tb.text_frame
        tf.word_wrap = True

        p = tf.paragraphs[0]
        r1 = p.add_run(f"Step {idx+1}: {step_title} — ")
        r1.font.bold = True
        r1.font.size = Pt(13)
        r1.font.color.rgb = CYAN if idx < 5 else (AMBER if idx == 5 else GREEN)
        r1.font.name = "Calibri"

        r2 = p.add_run(step_desc)
        r2.font.size = Pt(12)
        r2.font.color.rgb = WHITE
        r2.font.name = "Calibri"

    # =========================================================================
    # SLIDE 4: Live Project Demo & Real Case Studies
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "Live Project Demo: Real Database Case Studies", "PRACTICAL VERIFICATION")

    demo_cases = [
        ("Zero-Day Phishing", "https://secure-login-verify.top/auth", "DANGEROUS", "100 / 100", RED,
         "• PayPal brand mismatch on .top TLD\n• Credential harvester form detected\n• Urgent 'Account Suspension' lure\n• Missing HSTS & CSP headers"),
        ("Banking Impersonation", "https://secure-chase-update.bank-verify.xyz", "HIGH RISK", "88 / 100", AMBER,
         "• Chase Bank verification lure\n• Freshly registered .xyz domain\n• Deceptive financial keywords\n• Unverified intermediate CA"),
        ("Enterprise Application", "https://verified-safe-portal.com", "SAFE", "10 / 100", GREEN,
         "• Clean Let's Encrypt TLS cert\n• Complete HSTS & CSP enforcement\n• 0 malicious flags across all feeds\n• 94% confidence trust score")
    ]

    for idx, (title, url, verdict, score, color, findings) in enumerate(demo_cases):
        left = 0.8 + idx * 4.0
        add_card(s4, left, 1.8, 3.7, 4.8)
        tb = s4.shapes.add_textbox(Inches(left + 0.25), Inches(2.0), Inches(3.2), Inches(4.3))
        tf = tb.text_frame
        tf.word_wrap = True

        p1 = tf.paragraphs[0]
        p1.text = title.upper()
        p1.font.size = Pt(11)
        p1.font.bold = True
        p1.font.color.rgb = color
        p1.font.name = "Calibri"

        p_url = tf.add_paragraph()
        p_url.text = url
        p_url.font.size = Pt(10)
        p_url.font.italic = True
        p_url.font.color.rgb = SLATE
        p_url.font.name = "Calibri"
        p_url.space_after = Pt(6)

        p_score = tf.add_paragraph()
        p_score.text = f"{verdict} • Score: {score}"
        p_score.font.size = Pt(15)
        p_score.font.bold = True
        p_score.font.color.rgb = WHITE
        p_score.font.name = "Calibri"
        p_score.space_after = Pt(10)

        p_find = tf.add_paragraph()
        p_find.text = findings
        p_find.font.size = Pt(11.5)
        p_find.font.color.rgb = RGBColor(226, 232, 240)
        p_find.font.name = "Calibri"

    # =========================================================================
    # SLIDE 5: Core Product Capabilities
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "Platform Modules: Enterprise Cyber Protection", "PRODUCT SUITE")

    features = [
        ("3D Telemetry Dashboard", "Live security posture meter, 3D threat category visualizer, scan velocity graphs, and quick URL scanner.", CYAN),
        ("AI Security Assistant", "Conversational threat intelligence explaining technical risks and providing specific server remediations.", BLUE),
        ("Continuous Watchlist", "Automated background re-scans that monitor critical domains for certificate expiry and DNS tampering.", AMBER),
        ("Chrome Browser Extension", "Real-time zero-day protection displaying instant toolbar safety badges and pre-flight validation.", GREEN)
    ]

    for idx, (feat_title, feat_desc, col) in enumerate(features):
        x = 0.8 + (idx % 2) * 6.0
        y = 1.9 + (idx // 2) * 2.4
        add_card(s5, x, y, 5.7, 2.1)

        tb = s5.shapes.add_textbox(Inches(x + 0.3), Inches(y + 0.25), Inches(5.1), Inches(1.6))
        tf = tb.text_frame
        tf.word_wrap = True

        p_t = tf.paragraphs[0]
        p_t.text = feat_title
        p_t.font.size = Pt(17)
        p_t.font.bold = True
        p_t.font.color.rgb = col
        p_t.font.name = "Calibri"

        p_d = tf.add_paragraph()
        p_d.text = feat_desc
        p_d.font.size = Pt(12.5)
        p_d.font.color.rgb = RGBColor(226, 232, 240)
        p_d.font.name = "Calibri"
        p_d.space_before = Pt(6)

    # =========================================================================
    # SLIDE 6: Production Technology Stack & Resilience
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6)
    add_header(s6, "Technology Stack & Resilient Architecture", "ENGINEERING")

    stack_cards = [
        ("Frontend Application", "• React 19 & Vite 8\n• Tailwind CSS & Lucide Icons\n• Framer Motion 3D Graphics\n• Recharts Live Telemetry", CYAN),
        ("Backend Services", "• FastAPI High-Speed Async\n• Python 3.14+ Modern Runtime\n• SQLAlchemy 2.0 ORM\n• OpenAPI 3.1 Interactive Docs", BLUE),
        ("Dual-Engine Resilience", "• PostgreSQL 15 Primary Store\n• Auto-Fallback SQLite Dev Mode\n• Celery & Redis Task Queue\n• In-Process BackgroundTasks", AMBER),
        ("Extension & APIs", "• Chrome Manifest V3 Service Worker\n• Instant Pre-flight Heuristic Check\n• RESTful JSON Endpoints\n• Zero SSRF Attack Surface", GREEN)
    ]

    for idx, (title, items, col) in enumerate(stack_cards):
        left = 0.8 + idx * 3.0
        add_card(s6, left, 1.8, 2.75, 4.8)
        tb = s6.shapes.add_textbox(Inches(left + 0.2), Inches(2.1), Inches(2.35), Inches(4.2))
        tf = tb.text_frame
        tf.word_wrap = True

        p_t = tf.paragraphs[0]
        p_t.text = title
        p_t.font.size = Pt(15)
        p_t.font.bold = True
        p_t.font.color.rgb = col
        p_t.font.name = "Calibri"
        p_t.space_after = Pt(10)

        p_i = tf.add_paragraph()
        p_i.text = items
        p_i.font.size = Pt(11.5)
        p_i.font.color.rgb = RGBColor(226, 232, 240)
        p_i.font.name = "Calibri"

    # =========================================================================
    # SLIDE 7: Summary & Live Demo Links
    # =========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7)
    add_header(s7, "Conclusion: Real-Time Protection Ready for Action", "SUMMARY & ACCESS")

    add_card(s7, 0.8, 1.8, 11.733, 4.8)
    tb = s7.shapes.add_textbox(Inches(1.2), Inches(2.2), Inches(10.9), Inches(4.0))
    tf = tb.text_frame
    tf.word_wrap = True

    p1 = tf.paragraphs[0]
    p1.text = "Key Takeaways"
    p1.font.size = Pt(20)
    p1.font.bold = True
    p1.font.color.rgb = CYAN
    p1.font.name = "Calibri"

    p2 = tf.add_paragraph()
    p2.text = "✔ Multi-Vector Defense: Inspects DNS, TLS, Web Headers, DOM, and ML to catch zero-day phishing.\n✔ Zero Configuration Resilience: Dual-engine SQLite/Postgres and in-process task routing.\n✔ Comprehensive Suite: Web UI, 3D Telemetry, AI Assistant, Continuous Watchlist, and Chrome Extension."
    p2.font.size = Pt(14)
    p2.font.color.rgb = WHITE
    p2.font.name = "Calibri"
    p2.space_before = Pt(8)
    p2.space_after = Pt(20)

    p3 = tf.add_paragraph()
    p3.text = "Live Platform Access URLs"
    p3.font.size = Pt(18)
    p3.font.bold = True
    p3.font.color.rgb = GREEN
    p3.font.name = "Calibri"

    p4 = tf.add_paragraph()
    p4.text = "• Web Dashboard & Scanner:  http://localhost:5173\n• Backend API & Interactive Docs:  http://127.0.0.1:8000/docs\n• Subsystem Health Readiness Probe:  http://127.0.0.1:8000/api/v1/health"
    p4.font.size = Pt(13)
    p4.font.color.rgb = RGBColor(186, 230, 253)
    p4.font.name = "Calibri"
    p4.space_before = Pt(6)

    # Save presentation
    prs.save(output_path)
    print(f"Presentation saved to: {output_path}")

if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "TrustShield_Presentation.pptx"
    create_deck(out_file)
