# LMSGuardianG2

LMSGuardian v2 is a comprehensive link and content scanner built for Moodle-based LMS environments. It identifies external links, paywalls, file downloads, and content redirections to help assess information security risks across course content.

## 🚀 Quick Start

1. **Create a `.env` file** in the root of the project.

   Use this template:

   ```env
   MOODLE_USERNAME=
   MOODLE_PASSWORD=
   DATABASE_URL=
   GOOGLE_SAFE_KEY=
   EMAIL_USER=
   EMAIL_PASS=
   ```

2. **Install the dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the main script**:

   ```bash
   python scraper/main.py
   ```

## 📁 Folder Structure

```
LMSGuardianG2/
├── scraper/               # main scraper subsystem
│   └── main.py            # start scanning here
│   └── paywall/           # paywall and redirect detection logic
│   └── reportgenerator/   # report generator subsystem
│   └── reputation/        # VirusTotal cyber analyser here
│   └── scraper/           # scraping logic
├── .env                   # your local secrets (not tracked)
├── requirements.txt       # python dependencies
└── README.md              # you're reading this
```
