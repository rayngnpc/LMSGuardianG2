-- Drop tables if they already exist (in reverse dependency order)
DROP TABLE IF EXISTS scraped_contents;
DROP TABLE IF EXISTS reports;
DROP TABLE IF EXISTS scraper_sessions;
DROP TABLE IF EXISTS modules;
DROP TABLE IF EXISTS unit_coordinators;

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

-- Report Table
CREATE TABLE reports (
    report_id SERIAL PRIMARY KEY,
    session_id INT NOT NULL,
    module_id INT NOT NULL,
    report_type VARCHAR(100),
    report_content TEXT,
    CONSTRAINT fk_session FOREIGN KEY (session_id) REFERENCES scraper_sessions (session_id),
    CONSTRAINT fk_module_report FOREIGN KEY (module_id) REFERENCES modules (module_id)
);

-- ScrapedContent Table (with risk_score and risk_category)
CREATE TABLE scraped_contents (
    scraped_id SERIAL PRIMARY KEY,
    module_id INT NOT NULL,
    session_id INT NOT NULL,
    scraped_at TIMESTAMP,
    localurl TEXT, 
    url_link TEXT,
    risk_score FLOAT,
    risk_category TEXT,
    content_location TEXT,
    is_paywall BOOLEAN DEFAULT FALSE,
    apa7 TEXT,
    CONSTRAINT fk_module_scraped FOREIGN KEY (module_id) REFERENCES modules (module_id),
    CONSTRAINT fk_session_scraped FOREIGN KEY (session_id) REFERENCES scraper_sessions (session_id)
);

-- Insert Unit Coordinators
INSERT INTO unit_coordinators (full_name, email)
VALUES
    ('Chau Ng', '857@gmail.com'),
    ('GwanYoung Park', 'pgy6667@gmail.com'),
    ('Jasmine Berry', 'sheetpweri101@outlook.com'),
    ('Muhamad Syafiq', 'syafiqwork2023@gmail.com'),
    ('Admin Account', 'npchau95@gmail.com'),
    ('Admin User', 'npchau95@gmail.com');

-- Insert Modules linked to that UC
INSERT INTO modules (
    uc_id,
    module_name,
    teaching_period,
    semester,
    module_description,
    unit_code
)
VALUES
    (
        4,
        'ICT380 Information Security Policy and Governance',
        '2024',
        'TSA',
        'This unit introduces students to the advanced study of Information Security Policy and Governance at the organisational level. 
        Students will gain an understanding of standards and policies as well as international, national and local regulatory requirements 
        governing organisational information technology systems. The unit will address relevant data protection legislation, industry best practices, 
        risk management techniques and develop the necessary skills to evaluate and measure organisational compliance and to determine appropriate 
        organisational strategy to best support the information security needs.',
        1
    ),
    (
        3,
        'ICT285 Databases',
        '2024',
        'TJA',
        'This unit focuses on database design, implementation and management. Topics include data modelling, the relational model, non-relational databases,
         SQL, logical and physical database design, transaction management, recovery, security, and database administration. The theory material is complemented
         by practical work using common database management systems.',
        2
    ),
    (
        2,
        'ICT302 IT Professional Practice Project',
        '2025',
        'TMA',
        'This team-based university unit provides students with the opportunity to solve real-world problems across various domains. Projects will be carefully selected,
        and groups formed to best leverage the knowledge and skills acquired from each student’s respective major(s). Recognizing the interdisciplinary nature of the project,
        students will collaborate with team members from different IT majors to solve complex problems effectively. Emphasis will be placed on project management,
        interdisciplinary teamwork, professional communication with clients and stakeholders, and the delivery of relevant project outcomes. Furthermore, students will have 
        the opportunity to engage with industry professionals, allowing them to gain insights into IT professional practices. These industry engagement opportunities aim to 
        support students'' professional development and enhance their readiness for a successful career in the IT industry.',
        3
    ),
    (
        4,
        'POL298 International Political Economy',
        '2025',
        'TMA',
        'This unit introduces students to the discipline of international political economy. It is divided into three thematic sections. The first conceptually introduces the 
        discipline, considering its origins, the main theoretic traditions in the field, and the historical evolution of the global economy. A second thematic focus is on the
        development of liberal world order after WW2, its relationship to and impact on the developed and developing world, and its transformation with the growth of the global
        economy in more recent decades. A third thematic focus is on major challenges faced by the global political economy in what has become an era increasingly characterised
        by crises. What is the nature of crises, are they linked to key transformations in the IPE considered in the programme, such as the globalisation of production, trade,
        and finance, and the rise of new economically powerful states such as China? Can these crises be resolved through leadership and cooperation between states, or is the
        global political economy characterised by crises of leadership in which opportunities for international cooperation are diminishing?',
        4
    ),
    (
        1,
        'ICT280 Information Security Policy and Governance',
        '2025',
        'TMA',
        'This unit introduces students to the advanced study of Information Security Policy and Governance at the organisational level. Students will gain an understanding of 
        standards and policies as well as international, national and local regulatory requirements governing organisational information technology systems. The unit will address
        relevant data protection legislation, industry best practices, risk management techniques and develop the necessary skills to evaluate and measure organisational compliance
        and to determine appropriate organisational strategy to best support the information security needs.',
        5
    ),
    (
        1,
        'ICT302 IT Professional Practice Project',
        '2025',
        'TMA',
        'This team-based university unit provides students with the opportunity to solve real-world problems across various domains. Projects will be carefully selected, and groups
        formed to best leverage the knowledge and skills acquired from each student respective major(s). Recognizing the interdisciplinary nature of the project, students will
        collaborate with team members from different IT majors to solve complex problems effectively. Emphasis will be placed on project management, interdisciplinary teamwork, 
        professional communication with clients and stakeholders, and the delivery of relevant project outcomes. Furthermore, students will have the opportunity to engage with industry
        professionals, allowing them to gain insights into IT professional practices. These industry engagement opportunities aim to support students'' professional development and 
        enhance their readiness for a successful career in the IT industry.',
        6
    );
