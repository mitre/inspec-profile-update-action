control 'SV-213880' do
  title 'Software updates to SQL Server must be tested before being applied to production systems.'
  desc 'While it is important to apply SQL Server updates in a timely manner, it is also incumbent upon the database administrator and/or system administrator to ensure that their deployment will not interfere with the operation of the database and its applications.  Other than in emergency situations, SQL Server updates must be applied to appropriately configured non-production systems, and the resulting version of SQL Server assessed for correct operation.'
  desc 'check', 'Obtain evidence that SQL Server software updates are tested before being applied to production servers, and that any exceptions are approved by the ISSM.

If such evidence cannot be obtained, or the evidence that is obtained indicates a pattern of noncompliance, this is a finding.'
  desc 'fix', 'Institute and adhere to policies and procedures to ensure that SQL Server updates are tested prior to installation on production servers.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15099r312991_chk'
  tag severity: 'medium'
  tag gid: 'V-213880'
  tag rid: 'SV-213880r855552_rule'
  tag stig_id: 'SQL4-00-035500'
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag fix_id: 'F-15097r312992_fix'
  tag 'documentable'
  tag legacy: ['SV-82405', 'V-67915']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
