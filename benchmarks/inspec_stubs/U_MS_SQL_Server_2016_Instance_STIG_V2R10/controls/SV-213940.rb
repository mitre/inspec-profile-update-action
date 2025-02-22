control 'SV-213940' do
  title 'SQL Server must initiate session auditing upon startup.'
  desc "Session auditing is for use when a user's activities are under investigation. To be sure of capturing all activity during those periods when session auditing is in use, it needs to be in operation for the whole time SQL Server is running."
  desc 'check', "When Audits are enabled, they start up when the instance starts. 
https://msdn.microsoft.com/en-us/library/cc280386.aspx#Anchor_2 
 
Check if an audit is configured and enabled. 
 
Execute the following query: 
 
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
WHERE status_desc = 'STARTED' 
 
All currently defined audits for the SQL server instance will be listed. If no audits are returned, this is a finding."
  desc 'fix', "Configure the SQL Audit(s) to automatically start during system start-up.  
 
ALTER SERVER AUDIT [<Server Audit Name>] WITH STATE = ON 
 
Execute the following query: 
 
SELECT name AS 'Audit Name', 
  status_desc AS 'Audit Status', 
  audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
WHERE status_desc = 'STARTED' 
 
Ensure the SQL STIG Audit is configured to initiate session auditing upon startup."
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15157r313603_chk'
  tag severity: 'medium'
  tag gid: 'V-213940'
  tag rid: 'SV-213940r879562_rule'
  tag stig_id: 'SQL6-D0-004700'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag fix_id: 'F-15155r313604_fix'
  tag 'documentable'
  tag legacy: ['SV-93847', 'V-79141']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
