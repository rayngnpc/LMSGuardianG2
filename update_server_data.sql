-- ============================================================================
-- Update Server Database with Correct Module Data
-- ============================================================================
-- 
-- This script updates the server database to match the local database
-- with the correct module names and assignments
--
-- ============================================================================

BEGIN;

-- Update the modules table with correct data
-- Module ID 1 should be BSC203, Module ID 2 should be ICT280
UPDATE modules SET 
    module_name = 'BSC203 Introduction to ICT Research Methods',
    unit_code = 'BSC203',
    module_description = 'Introduction to research methods and practices in ICT.',
    teaching_period = 'Semester 1',
    semester = '2025'
WHERE module_id = 1;

UPDATE modules SET 
    module_name = 'ICT280 Information Security Policy and Governance',
    unit_code = 'ICT280',
    module_description = 'Information security policy development and governance frameworks.',
    teaching_period = 'Semester 1',
    semester = '2025'
WHERE module_id = 2;

-- Update unit coordinator if needed
UPDATE unit_coordinators SET 
    full_name = 'Peter Col',
    email = 'npchau95@gmail.com'
WHERE uc_id = 1;

-- Show the updated data
SELECT 'Updated Unit Coordinators:' as info;
SELECT uc_id, full_name, email FROM unit_coordinators;

SELECT '';
SELECT 'Updated Modules:' as info;
SELECT module_id, module_name, unit_code, uc_id FROM modules ORDER BY module_id;

COMMIT;

SELECT 'Server data updated successfully!' as status;
