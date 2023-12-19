control 'SV-213936' do
  title 'SQL Server must be configured to generate audit records for DoD-defined auditable events within all DBMS/database components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.  
 
Audit records can be generated from various components within SQL Server (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records. 
 
DoD has defined the list of events for which SQL Server will provide an audit record generation capability as the following:  
 
(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels); 
 
(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and 
 
(iii) All account creation, modification, disabling, and termination actions. 
 
Organizations may define additional events requiring continuous or ad hoc auditing.'
  desc 'check', "Review the server documentation to determine if any additional events are required to be audited. If no additional events are required, this is not a finding. 
 
Execute the following query to get all of the installed audits: 
 
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
 
All currently defined audits for the SQL server instance will be listed. If no audits are returned, this is a finding.  
 
To view the actions being audited by the audits, execute the following query: 
 
SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 
 
Compare the documentation to the list of generated audit events. If there are any missing events, this is a finding."
  desc 'fix', 'Add all required audit events to the STIG Compliant audit specification server documentation.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15153r313591_chk'
  tag severity: 'medium'
  tag gid: 'V-213936'
  tag rid: 'SV-213936r879559_rule'
  tag stig_id: 'SQL6-D0-004300'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-15151r313592_fix'
  tag 'documentable'
  tag legacy: ['SV-93839', 'V-79133']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
