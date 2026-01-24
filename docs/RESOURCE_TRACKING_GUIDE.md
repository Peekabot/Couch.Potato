# Resource Tracking & Partnership Guide

## Purpose
Track which educational and credential resources drive the most value for veterans, optimize resource offerings, and build local partnerships with training providers.

---

## Tracking Implementation

### UTM Parameters (for Analytics)

**Format**: `?utm_source=vhcp&utm_medium=resources&utm_campaign=[resource_name]`

**Example Links**:
```
CLEP: https://clep.collegeboard.org/?utm_source=vhcp&utm_medium=resources&utm_campaign=clep
AHA CPR: https://cpr.heart.org/en/courses?utm_source=vhcp&utm_medium=resources&utm_campaign=cpr
VA Benefits: https://www.va.gov/education/eligibility/?utm_source=vhcp&utm_medium=resources&utm_campaign=gi-bill
SBA: https://www.sba.gov/business-guide/grow-your-business/veteran-owned-businesses?utm_source=vhcp&utm_medium=resources&utm_campaign=sba
Coursera: https://www.coursera.org/career-academy?utm_source=vhcp&utm_medium=resources&utm_campaign=coursera
```

**What to Track**:
- **Clicks**: How many veterans click each resource link?
- **Source**: Where did the click originate (onboarding email, resource hub, discovery call follow-up)?
- **Conversion**: Did the veteran complete the action (register for CLEP, enroll in Coursera, book CPR class)?
- **Feedback**: Did the veteran report value from the resource?

---

## Analytics Setup

### Option 1: Google Analytics 4 (GA4)

**Setup**:
1. Create GA4 property for your domain
2. Add GA4 tracking code to all pages (header or footer)
3. Enable enhanced measurement (outbound clicks)

**Custom Events** (track resource clicks):
```javascript
// In resources.html or onboarding emails
gtag('event', 'resource_click', {
  'resource_category': 'education', // education, certification, funding, training
  'resource_name': 'clep',
  'resource_url': 'https://clep.collegeboard.org',
  'click_source': 'resource_hub' // resource_hub, email, onboarding_card
});
```

**Reports to Build**:
- **Top Resources**: Which resources get the most clicks?
- **Conversion Funnel**: Intake → Resource Hub Visit → Resource Click → Feedback/Completion
- **Cohort Analysis**: Do veterans who use resources (e.g., CLEP) have higher business success rates?

---

### Option 2: Custom Analytics (Lightweight)

**Database Schema** (PostgreSQL):

```sql
CREATE TABLE resource_clicks (
  id SERIAL PRIMARY KEY,
  client_id INT REFERENCES clients(id),
  resource_name VARCHAR(50) NOT NULL, -- clep, aha_cpr, va_benefits, sba, etc.
  resource_category VARCHAR(50), -- education, certification, funding, training
  click_source VARCHAR(50), -- resource_hub, email, onboarding_card
  clicked_at TIMESTAMP DEFAULT NOW(),
  user_agent TEXT,
  referrer TEXT
);

CREATE INDEX idx_resource_clicks_name ON resource_clicks(resource_name);
CREATE INDEX idx_resource_clicks_client ON resource_clicks(client_id);
```

**Track Clicks** (Flask API endpoint):

```python
@app.route('/api/track/resource', methods=['POST'])
def track_resource_click():
    data = request.json
    db.execute("""
        INSERT INTO resource_clicks (client_id, resource_name, resource_category, click_source, user_agent, referrer)
        VALUES (%(client_id)s, %(resource_name)s, %(resource_category)s, %(click_source)s, %(user_agent)s, %(referrer)s)
    """, {
        'client_id': data.get('client_id'),
        'resource_name': data['resource_name'],
        'resource_category': data['resource_category'],
        'click_source': data['click_source'],
        'user_agent': request.headers.get('User-Agent'),
        'referrer': request.headers.get('Referer')
    })
    return jsonify({'status': 'ok'})
```

**Monthly Report Query**:

```sql
-- Top 10 resources by clicks (last 30 days)
SELECT
  resource_name,
  COUNT(*) as clicks,
  COUNT(DISTINCT client_id) as unique_veterans
FROM resource_clicks
WHERE clicked_at >= NOW() - INTERVAL '30 days'
GROUP BY resource_name
ORDER BY clicks DESC
LIMIT 10;

-- Clicks by source (email vs resource hub)
SELECT
  click_source,
  COUNT(*) as clicks
FROM resource_clicks
WHERE clicked_at >= NOW() - INTERVAL '30 days'
GROUP BY click_source
ORDER BY clicks DESC;
```

---

## Feedback Collection

### Post-Resource Survey (Email or In-App)

**Send 2-4 weeks after resource click**:

**Subject**: Did [CLEP / CPR / VA Benefits] help you? Quick 2-minute survey

**Body**:
```
Hi [First Name],

A few weeks ago, you explored our [CLEP Exam / CPR Certification / VA Benefits] resource. We'd love to hear how it went!

Quick Survey (2 minutes):
1. Did you take action on this resource?
   [ ] Yes, I registered/enrolled
   [ ] Yes, I'm researching but haven't enrolled yet
   [ ] No, I decided it wasn't right for me
   [ ] No, I encountered a barrier (please explain below)

2. How valuable was this resource to your business or career goals?
   [ ] Extremely valuable (5/5)
   [ ] Very valuable (4/5)
   [ ] Somewhat valuable (3/5)
   [ ] Not very valuable (2/5)
   [ ] Not valuable at all (1/5)

3. What outcome did you achieve (or expect to achieve)?
   [ ] Earned college credit (saved $_____ on tuition)
   [ ] Got certified (CPR, First Aid, etc.)
   [ ] Secured funding (GI Bill, SBA loan, etc.)
   [ ] Learned new skills (completed course)
   [ ] Other: _______________

4. Would you recommend this resource to other veterans?
   [ ] Definitely
   [ ] Probably
   [ ] Not sure
   [ ] Probably not
   [ ] Definitely not

5. Any suggestions for improving how we present or support this resource?
   [Free text box]

[Submit Survey Button]

Thank you for helping us serve veterans better!

- Veteran Holding Company Platform Team
```

**Store Results** (Database):

```sql
CREATE TABLE resource_feedback (
  id SERIAL PRIMARY KEY,
  client_id INT REFERENCES clients(id),
  resource_name VARCHAR(50),
  took_action BOOLEAN,
  value_rating INT CHECK (value_rating BETWEEN 1 AND 5),
  outcome TEXT,
  would_recommend VARCHAR(50),
  suggestions TEXT,
  submitted_at TIMESTAMP DEFAULT NOW()
);
```

---

## Partnership Development

### Local Provider Partnerships

**Objective**: Build relationships with local CLEP testing centers, AHA CPR instructors, SBDC advisors, and community colleges to offer co-branded workshops and discounts.

---

### 1. AHA CPR Instructors (High-Value, Low-Effort)

**Outreach Template**:

**Subject**: Partnership Opportunity - Veteran CPR Training Referrals

```
Dear [Instructor Name],

I run the Veteran Holding Company Platform, a service helping veterans start businesses and build wealth. Many of our clients need CPR and First Aid certification for their small businesses (gyms, childcare, event hosting, etc.).

I'd love to explore a partnership where we refer veterans to your AHA classes in exchange for:
- 10-15% veteran discount (optional, but appreciated)
- Priority booking for our clients
- Co-branded workshop opportunities (e.g., "Veteran Business Safety Day")

We currently serve [X] veterans per month in [City/Region] and expect to grow to [3X] by year-end.

Would you be open to a 15-minute call to discuss how we can support each other?

Best regards,
[Your Name]
Founder, Veteran Holding Company Platform
[Phone] | [Email]
```

**Expected Outcomes**:
- **Referral agreement**: You send veterans, instructor offers 10% discount
- **Co-branded workshops**: Host quarterly "Veteran Safety Certification Day" (CPR + First Aid for 10-15 veterans at group rate)
- **Revenue share** (optional): Instructor pays you $10-$20 per referral (or you waive it to keep pricing low for veterans)

**Tracking**:
- Send personalized referral links: `https://cpr.heart.org?ref=vhcp-[instructor-name]`
- Ask instructor to report monthly enrollments from referrals
- Survey veterans post-certification for feedback

---

### 2. Community Colleges (CLEP Testing Centers)

**Outreach Template**:

**Subject**: Veteran CLEP Partnership - Free Workshop + Testing Referrals

```
Dear [Registrar / Veteran Services Coordinator],

I represent the Veteran Holding Company Platform, serving [X] veterans in [Region]. We help veterans accelerate degree completion using CLEP exams and GI Bill benefits.

I'd like to propose a partnership:
1. **Free CLEP Workshop**: We host a 1-hour "CLEP for Veterans" workshop at your campus (virtual or in-person) to educate veterans about credit-by-exam options.
2. **Testing Referrals**: We refer veterans to your CLEP testing center for exam registration.
3. **Enrollment Pipeline**: Veterans who earn CLEP credits may enroll in your degree programs (increasing veteran enrollment).

Benefits to [College Name]:
- Increased veteran enrollment and retention
- Positive community engagement (supporting veteran education)
- Access to our veteran network for marketing

Benefits to Veterans:
- Free CLEP guidance and prep resources
- Local testing center (no travel to distant sites)
- Streamlined credit transfer process

Would you be open to a brief call to explore this partnership?

Best regards,
[Your Name]
[Title]
[Contact Info]
```

**Expected Outcomes**:
- **Co-hosted workshop**: College provides space/promotion, you provide content
- **Referral pipeline**: Veterans test at college, potentially enroll for degree
- **Data sharing**: College reports how many referred veterans enroll (measure partnership ROI)

---

### 3. SBA / SBDC (Small Business Development Centers)

**Outreach Template**:

**Subject**: Collaboration Opportunity - Veteran Business Formation + SBA Training

```
Dear [SBDC Director / Advisor],

I'm the founder of the Veteran Holding Company Platform, a service that helps veterans form LLCs, set up trusts, and launch small businesses. We've worked with [X] veteran entrepreneurs in [Region] over the past [Y] months.

Many of our clients need SBA training on business planning, financing, and marketing—areas where your SBDC excels. I'd like to explore a collaboration:

1. **Cross-Referrals**: We refer veterans to your SBDC for free counseling and training; you refer veterans to us for entity formation and legal structuring.
2. **Co-Hosted Webinars**: Quarterly webinar series on "Veteran Business Basics" (you cover business planning, we cover entity/trust setup).
3. **Bundled Services**: Veterans who complete your business plan workshop get a discount on our Starter package ($1,500 → $1,200).

This partnership would help veterans access comprehensive support (legal + business) in one coordinated effort.

Are you available for a 20-minute call next week to discuss?

Best regards,
[Your Name]
[Contact Info]
```

**Expected Outcomes**:
- **Referral agreement**: SBDC refers veterans who need legal setup; you refer veterans who need business planning
- **Co-branded webinars**: Reach wider veteran audience
- **Client success stories**: Jointly publish case studies of veteran businesses that used both services

---

## Monetization (Optional)

### Affiliate Programs

**Coursera**:
- **Program**: Coursera Affiliate Program
- **Commission**: 20-45% of first enrollment (varies by course)
- **Link Format**: `https://www.coursera.org/course-name?ranMID=40328&ranEAID=yourID&ranSiteID=yourSiteID`
- **Application**: https://www.coursera.org/about/partners/affiliate

**Udemy**:
- **Program**: Udemy Affiliate Program
- **Commission**: 15% of course sales (higher for bestsellers)
- **Link Format**: `https://www.udemy.com/course-name/?couponCode=yourCode&ranMID=39197&ranEAID=yourID`
- **Application**: https://www.udemy.com/affiliate/

**Disclosure**:
Always disclose affiliate relationships on resource pages:
> *This link includes a referral code. If you enroll, we may receive a small commission at no extra cost to you. This helps us provide free resources to veterans.*

---

## Performance Metrics

### Key Metrics to Track

| Metric | Target (Month 3) | Target (Month 6) | How to Measure |
|--------|-----------------|------------------|----------------|
| **Resource Hub Visits** | 100/month | 300/month | Google Analytics |
| **Resource Clicks** | 50/month | 150/month | UTM tracking |
| **Email Template Downloads** | 20/month | 60/month | Download tracking |
| **Partner Referrals** | 5/month | 15/month | Partner reporting |
| **Feedback Surveys Completed** | 10/month | 30/month | Survey tool |
| **Resource Completion Rate** | 30% | 50% | Follow-up surveys |
| **Client NPS (Resource Impact)** | 7/10 | 8/10 | NPS survey |

### Monthly Report Template

```markdown
# Resource Performance Report - [Month Year]

## Overview
- Total resource hub visits: [X]
- Total resource clicks: [Y]
- Top 3 resources: [CLEP, VA Benefits, CPR]
- Conversion rate (click → completion): [Z%]

## Top Performing Resources
1. **CLEP Exams**: [X] clicks, [Y] completions (saved veterans $[Z] in tuition)
2. **VA Education Benefits**: [X] clicks, [Y] GI Bill applications
3. **CPR Certification**: [X] clicks, [Y] certifications earned

## Veteran Feedback Highlights
- "CLEP saved me $3,000 on my degree. Thank you!"
- "The VA benefits email template made it so easy to apply."
- "Got CPR certified in one day—required for my gym business."

## Partnerships
- **New partnerships**: [AHA Instructor Name], [College Name SBDC]
- **Referrals sent**: [X] to CPR classes, [Y] to SBDC
- **Referrals received**: [Z] from SBDC

## Action Items for Next Month
- [ ] Add [New Resource] to hub
- [ ] Schedule co-hosted webinar with [Partner]
- [ ] Improve CTAs on low-performing resources
- [ ] Send feedback surveys to [X] recent resource users
```

---

## Tools & Software

### Recommended Tools

| Tool | Purpose | Cost |
|------|---------|------|
| **Google Analytics 4** | Track clicks, conversions, funnels | Free |
| **Typeform / Tally** | Feedback surveys | Free - $35/mo |
| **Calendly** | Schedule partnership calls | Free - $12/mo |
| **Mailchimp / SendGrid** | Email drip campaigns, surveys | Free - $20/mo |
| **Airtable / Notion** | Track partnerships, referrals | Free - $10/mo |
| **Bitly / Rebrandly** | Shorten and track referral links | Free - $29/mo |

---

## Quick Implementation Checklist

**Week 1**:
- [ ] Add UTM parameters to all resource links in resources.html
- [ ] Set up Google Analytics 4 (or custom tracking database)
- [ ] Create feedback survey template (Typeform)
- [ ] Draft 3 partnership outreach emails (AHA, SBDC, college)

**Week 2**:
- [ ] Send partnership outreach to 5 local providers (2 CPR, 2 SBDC, 1 college)
- [ ] Add privacy disclosure to resources.html
- [ ] Test tracking: Click resource links and verify data in analytics

**Week 3**:
- [ ] Schedule partnership calls with interested providers
- [ ] Send first batch of feedback surveys (to veterans who clicked resources 2-4 weeks ago)
- [ ] Review analytics: Identify top 3 resources

**Week 4**:
- [ ] Finalize 1-2 partnership agreements
- [ ] Generate first monthly resource performance report
- [ ] Plan co-hosted workshop or webinar for Month 2

---

## Long-Term Strategy

### Year 1 Goals
- **10+ local partnerships** (CPR instructors, SBDCs, colleges, banks)
- **500+ resource clicks/month** from veteran clients
- **70%+ resource completion rate** (veterans take action after clicking)
- **5 co-hosted workshops/webinars** with partners

### Scaling Nationally
- **Partner marketplace**: Build directory of vetted CPR instructors, SBDCs, and colleges in all 50 states
- **Automated referrals**: Veterans enter ZIP code → see local partners → book instantly
- **Revenue share**: Negotiate 5-10% revenue share with partners (reinvest in free services for veterans)

---

**Questions? Contact partnerships@veteranholdingco.com**

🎖️ **Empowering veterans through education, credentials, and community partnerships.**
