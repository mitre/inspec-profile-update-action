control 'SV-24801' do
  title 'Attempts to bypass access controls should be audited.'
  desc 'Configuring proper auditing is critical to recording any malicious events or detecting when attacks on the database occur. Auditing can be turned on for any SQL statement or any use of a system privilege. Auditing can be enabled for all users (system wide) or for specific users. You may indicate whether one audit record for each access to an object or one audit record for the entire session is generated. You can enable auditing for commands that result in success, commands that result in failure, or both. Not all audit options can be audited by session. Audit options set using the BY SESSION clause for those actions that will not produce a session audit record will default to BY ACCESS.'
  desc 'check', "From SQL*Plus:

  select name from stmt_audit_option_map
  where name not in
  (select audit_option from dba_stmt_audit_opts)
  and name not in
  ('ALL STATEMENTS', 'ANALYZE ANY DICTIONARY',
   'CREATE DIRECTORY', 'DEBUG CONNECT ANY',
   'DEBUG CONNECT USER', 'DELETE ANY TABLE',
   'DELETE TABLE', 'DROP DIRECTORY',
   'EXECUTE ANY LIBRARY', 'EXECUTE ANY PROCEDURE',
   'EXECUTE ANY TYPE', 'EXECUTE LIBRARY',
   'EXECUTE PROCEDURE', 'EXISTS', 'GRANT LIBRARY',
   'INSERT ANY TABLE', 'INSERT TABLE', 'LOCK TABLE',
   'NETWORK', 'OUTLINE', 'READUP', 'READUP DBHIGH',
   'SELECT ANY DICTIONARY', 'SELECT ANY SEQUENCE',
   'SELECT ANY TABLE', 'SELECT MINING MODEL',
   'SELECT SEQUENCE', 'SELECT TABLE',
   'UPDATE ANY TABLE', 'UPDATE TABLE', 'USE EDITION',
   'WRITEDOWN', 'WRITEDOWN DBLOW', 'WRITEUP',
   'WRITEUP DBHIGH');

If any audit options are returned, this is a finding."
  desc 'fix', 'There are three types of auditable events: 1) Use of system privileges, 2) Use of object privileges, and 3) Issuance of statements. Activating some auditing options sometimes activates others. For example, the use of a system privilege requires the issuance of a system command. Auditing for use of the privilege also audits for the statement.

Configure auditing for Oracle using the following script.  If the Check reports audit option names not included in this script, augment it with one additional statement per option reported:

From SQL*Plus:
  audit all by access;
  audit all privileges by access;
  audit alter database link by access;
  audit alter java class by access;
  audit alter java resource by access;
  audit alter java source by access;
  audit alter mining model by access;
  audit alter public database link by access;
  audit alter sequence by access;
  audit alter table by access;
  audit comment edition by access;
  audit comment mining model by access;
  audit comment table by access;
  audit create java class by access;
  audit create java resource by access;
  audit create java source by access;
  audit debug procedure by access;
  audit drop java class by access;
  audit drop java resource by access;
  audit drop java source by access;
  audit execute assembly;
  audit exempt access policy by access;
  audit exempt identity policy by access;
  audit grant directory by access;
  audit grant edition by access;
  audit grant mining model by access;
  audit grant procedure by access;
  audit grant sequence by access;
  audit grant table by access;
  audit grant type by access;
  audit sysdba by access;
  audit sysoper by access;

The following SQL statements will disable audits set by the commands above that are not required:

  noaudit execute library;
  audit rename on default by access;

If application objects have already been created, then the audit rename on object statement should be issued for all application objects.

From SQL*Plus:

  audit rename on [application object name] by access;'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-26453r3_chk'
  tag severity: 'medium'
  tag gid: 'V-15644'
  tag rid: 'SV-24801r3_rule'
  tag stig_id: 'DG0141-ORACLE11'
  tag gtitle: 'DBMS access control bypass'
  tag fix_id: 'F-22791r4_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
