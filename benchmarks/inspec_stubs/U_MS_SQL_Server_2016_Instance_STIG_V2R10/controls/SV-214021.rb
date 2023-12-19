control 'SV-214021' do
  title 'SQL Server must generate audit records for all direct access to the database(s).'
  desc 'In this context, direct access is any query, command, or call to SQL Server that comes from any source other than the application(s) that it supports. Examples would be the command line or a database management utility program. The intent is to capture all activity from administrative and non-standard sources.'
  desc 'check', 'Determine whether any Server Audits are configured to filter records. From SQL Server Management Studio execute the following query: 
 
SELECT name AS AuditName, predicate AS AuditFilter  
FROM sys.server_audits  
WHERE predicate IS NOT NULL 
 
If any audits are returned, review the associated filters to determine whether administrative activities are being excluded.  
 
If any audits are configured to exclude administrative activities, this is a finding.'
  desc 'fix', 'Check the system documentation for required SQL Server Audits. Remove any Audit filters that exclude or reduce required auditing. Update filters to ensure administrative activity is not excluded.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15238r313846_chk'
  tag severity: 'medium'
  tag gid: 'V-214021'
  tag rid: 'SV-214021r879879_rule'
  tag stig_id: 'SQL6-D0-015500'
  tag gtitle: 'SRG-APP-000508-DB-000358'
  tag fix_id: 'F-15236r313847_fix'
  tag 'documentable'
  tag legacy: ['SV-94009', 'V-79303']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
