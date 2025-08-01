control 'SV-206638' do
  title 'The DBMS must generate audit records for all direct access to the database(s).'
  desc 'In this context, direct access is any query, command, or call to the DBMS that comes from any source other than the application(s) that it supports. Examples would be the command line or a database management utility program. The intent is to capture all activity from administrative and non-standard sources.'
  desc 'check', 'If the DBMS does not generate audit records for all direct access to the database(s), this is a finding.'
  desc 'fix', 'Configure the DBMS to generate audit records for all direct access to the database(s).'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6898r291582_chk'
  tag severity: 'medium'
  tag gid: 'V-206638'
  tag rid: 'SV-206638r617447_rule'
  tag stig_id: 'SRG-APP-000508-DB-000358'
  tag gtitle: 'SRG-APP-000508'
  tag fix_id: 'F-6898r291583_fix'
  tag 'documentable'
  tag legacy: ['SV-72553', 'V-58123']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
