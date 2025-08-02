--
-- PostgreSQL database dump
--

-- Dumped from database version 15.13 (Debian 15.13-0+deb12u1)
-- Dumped by pg_dump version 15.13 (Debian 15.13-0+deb12u1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: modules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.modules (
    module_id integer NOT NULL,
    uc_id integer NOT NULL,
    module_name character varying(255) NOT NULL,
    teaching_period character varying(50),
    semester character varying(50),
    module_description text,
    unit_code character varying(50)
);


--
-- Name: modules_module_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.modules_module_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: modules_module_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.modules_module_id_seq OWNED BY public.modules.module_id;


--
-- Name: scraped_contents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scraped_contents (
    scraped_id integer NOT NULL,
    module_id integer NOT NULL,
    session_id integer NOT NULL,
    scraped_at timestamp without time zone,
    localurl text,
    url_link text,
    risk_score double precision,
    risk_category text,
    content_location text,
    is_paywall boolean DEFAULT false,
    apa7 text
);


--
-- Name: scraped_contents_scraped_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.scraped_contents_scraped_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scraped_contents_scraped_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.scraped_contents_scraped_id_seq OWNED BY public.scraped_contents.scraped_id;


--
-- Name: scraper_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scraper_sessions (
    session_id integer NOT NULL,
    started_at timestamp without time zone,
    ended_at timestamp without time zone,
    completion_status character varying(50),
    error_log text,
    module_id integer
);


--
-- Name: scraper_sessions_session_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.scraper_sessions_session_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scraper_sessions_session_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.scraper_sessions_session_id_seq OWNED BY public.scraper_sessions.session_id;


--
-- Name: unit_coordinators; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.unit_coordinators (
    uc_id integer NOT NULL,
    full_name character varying(255) NOT NULL,
    email character varying(255) NOT NULL
);


--
-- Name: unit_coordinators_uc_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.unit_coordinators_uc_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: unit_coordinators_uc_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.unit_coordinators_uc_id_seq OWNED BY public.unit_coordinators.uc_id;


--
-- Name: modules module_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.modules ALTER COLUMN module_id SET DEFAULT nextval('public.modules_module_id_seq'::regclass);


--
-- Name: scraped_contents scraped_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scraped_contents ALTER COLUMN scraped_id SET DEFAULT nextval('public.scraped_contents_scraped_id_seq'::regclass);


--
-- Name: scraper_sessions session_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scraper_sessions ALTER COLUMN session_id SET DEFAULT nextval('public.scraper_sessions_session_id_seq'::regclass);


--
-- Name: unit_coordinators uc_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unit_coordinators ALTER COLUMN uc_id SET DEFAULT nextval('public.unit_coordinators_uc_id_seq'::regclass);


--
-- Name: modules modules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.modules
    ADD CONSTRAINT modules_pkey PRIMARY KEY (module_id);


--
-- Name: scraped_contents scraped_contents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scraped_contents
    ADD CONSTRAINT scraped_contents_pkey PRIMARY KEY (scraped_id);


--
-- Name: scraper_sessions scraper_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scraper_sessions
    ADD CONSTRAINT scraper_sessions_pkey PRIMARY KEY (session_id);


--
-- Name: unit_coordinators unit_coordinators_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unit_coordinators
    ADD CONSTRAINT unit_coordinators_pkey PRIMARY KEY (uc_id);


--
-- Name: scraped_contents fk_module_scraped; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scraped_contents
    ADD CONSTRAINT fk_module_scraped FOREIGN KEY (module_id) REFERENCES public.modules(module_id);


--
-- Name: scraper_sessions fk_scraper_module; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scraper_sessions
    ADD CONSTRAINT fk_scraper_module FOREIGN KEY (module_id) REFERENCES public.modules(module_id);


--
-- Name: scraped_contents fk_session_scraped; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scraped_contents
    ADD CONSTRAINT fk_session_scraped FOREIGN KEY (session_id) REFERENCES public.scraper_sessions(session_id);


--
-- Name: modules fk_uc; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.modules
    ADD CONSTRAINT fk_uc FOREIGN KEY (uc_id) REFERENCES public.unit_coordinators(uc_id);


--
-- PostgreSQL database dump complete
--

