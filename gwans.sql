-- Drop views or dependent objects first
DROP VIEW IF EXISTS citation_statistics CASCADE;

-- Drop tables in reverse dependency order with CASCADE
DROP TABLE IF EXISTS scraped_contents CASCADE;
DROP TABLE IF EXISTS reports CASCADE;
DROP TABLE IF EXISTS scraper_sessions CASCADE;
DROP TABLE IF EXISTS modules CASCADE;
DROP TABLE IF EXISTS unit_coordinators CASCADE;


-- UnitCoordinator Table
CREATE TABLE unit_coordinators (
    uc_id SERIAL PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL
);

-- Module Table
CREATE TABLE modules (
    module_id SERIAL PRIMARY KEY,
    uc_id INT NOT NULL,
    module_name VARCHAR(255) NOT NULL,
    teaching_period VARCHAR(50),
    semester VARCHAR(50),
    module_description TEXT,
    unit_code VARCHAR(50),
    CONSTRAINT fk_uc FOREIGN KEY (uc_id) REFERENCES unit_coordinators (uc_id)
);

-- ScraperSession Table
CREATE TABLE scraper_sessions (
    session_id SERIAL PRIMARY KEY,
    started_at TIMESTAMP,
    ended_at TIMESTAMP,
    completion_status VARCHAR(50),
    error_log TEXT,
    module_id INT,
    CONSTRAINT fk_scraper_module FOREIGN KEY (module_id) REFERENCES modules (module_id)
);

-- ScrapedContent Table (with risk_score and risk_category)
CREATE TABLE scraped_contents (
    scraped_id SERIAL PRIMARY KEY,
    module_id INT NOT NULL,
    session_id INT NOT NULL,
    scraped_at TIMESTAMP,
    localurl TEXT,
    url_link TEXT,
    risk_score DOUBLE PRECISION,
    risk_category TEXT,
    content_location TEXT,
    is_paywall BOOLEAN DEFAULT FALSE,
    apa7 TEXT,
    CONSTRAINT fk_module_scraped FOREIGN KEY (module_id) REFERENCES modules (module_id),
    CONSTRAINT fk_session_scraped FOREIGN KEY (session_id) REFERENCES scraper_sessions (session_id)
);


-- Insert Unit Coordinators
INSERT INTO
    unit_coordinators (full_name, email)
VALUES ('Chau Ng', 'npchau95@gmail.com'),
    (
        'GwanYoung Park',
        'pgy6667@gmail.com'
    ),
    (
        'Jasmine Berry',
        'cosmicowl045@gmail.com'
    ),
    (
        'Muhamad Syafiq',
        'syafiqwork2023@gmail.com'
    ),
    (
        'Admin Account',
        'npchau95@gmail.com'
    ),
    (
        'Admin User',
        'npchau95@gmail.com'
    );

--- Insert Modules linked to that UC in the requested order:
INSERT INTO
    modules (
        module_id,
        uc_id,
        module_name,
        teaching_period,
        semester,
        module_description,
        unit_code
    )
VALUES (
        1,
        1,
        'Introduction to ICT Research Methods',
        '2025',
        'TJA',
        'This unit provides an introduction to research in the information and communications technology (ICT) discipline. It explores the kinds of research questions addressed in 
        ICT research, and provides an opportunity for students to understand the broad range of research approaches used in ICT research including: design research, experimental research,
        survey research, action research and case study research. Students will develop both research and project management skills and gain the knowledge and skills needed to
        critically evaluate the ICT research literature.',
        'BSC203'
    ),
    (
        2,
        2,
        'Information Security Policy and Governance',
        '2025',
        'TMA',
        'This unit introduces students to the advanced study of Information Security Policy and Governance at the organisational level. Students will gain an understanding of 
        standards and policies as well as international, national and local regulatory requirements governing organisational information technology systems. The unit will address
        relevant data protection legislation, industry best practices, risk management techniques and develop the necessary skills to evaluate and measure organisational compliance
        and to determine appropriate organisational strategy to best support the information security needs.',
        'ICT280'
    ),
    (
        3,
        3,
        'International Political Economy',
        '2025',
        'TMA',
        'This unit introduces students to the discipline of international political economy. It is divided into three thematic sections. The first conceptually introduces the 
        discipline, considering its origins, the main theoretic traditions in the field, and the historical evolution of the global economy. A second thematic focus is on the
        development of liberal world order after WW2, its relationship to and impact on the developed and developing world, and its transformation with the growth of the global
        economy in more recent decades. A third thematic focus is on major challenges faced by the global political economy in what has become an era increasingly characterised
        by crises. What is the nature of crises, are they linked to key transformations in the IPE considered in the programme, such as the globalisation of production, trade,
        and finance, and the rise of new economically powerful states such as China? Can these crises be resolved through leadership and cooperation between states, or is the
        global political economy characterised by crises of leadership in which opportunities for international cooperation are diminishing?',
        'POL298'
    ),
    (
        8,
        4,
        'Analysis of Different Type of Links found in Moodle LMS',
        '2025',
        'TMA',
        'This course page is built to show that no reports will be sent when there is no external links or third-party referencces.',
        'ICT567'
    );