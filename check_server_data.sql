-- Check current data in server database
SELECT 'Unit Coordinators on Server:' as section;
SELECT uc_id, full_name, email FROM unit_coordinators ORDER BY uc_id;

SELECT '';
SELECT 'Modules on Server:' as section;
SELECT module_id, module_name, unit_code, uc_id FROM modules ORDER BY module_id;

SELECT '';
SELECT 'Latest Scraper Session:' as section;
SELECT session_id, started_at, completion_status FROM scraper_sessions ORDER BY session_id DESC LIMIT 5;
