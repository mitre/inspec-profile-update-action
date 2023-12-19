control 'SV-222621' do
  title 'The ISSO must ensure application audit trails are retained for at least 1 year for applications without SAMI data, and 5 years for applications including SAMI data.'
  desc 'Log files are a requirement to trace intruder activity or to audit user activity.'
  desc 'check', 'Verify a process is in place to retain application audit log files for one year and five years for SAMI data.

If audit logs have not been retained for one year or five years for SAMI data, this is a finding.'
  desc 'fix', 'Retain application audit log files for one year and five years for SAMI data.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24291r493771_chk'
  tag severity: 'medium'
  tag gid: 'V-222621'
  tag rid: 'SV-222621r864406_rule'
  tag stig_id: 'APSC-DV-002900'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24280r493772_fix'
  tag 'documentable'
  tag legacy: ['SV-84917', 'V-70295']
  tag cci: ['CCI-000167']
  tag nist: ['AU-11']
end
