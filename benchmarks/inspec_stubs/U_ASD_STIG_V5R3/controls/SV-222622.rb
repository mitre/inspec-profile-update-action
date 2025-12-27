control 'SV-222622' do
  title 'The ISSO must review audit trails periodically based on system documentation recommendations or immediately upon system security events.'
  desc 'Without access control the data is not secure. It can be compromised, misused, or changed by unauthorized access at any time.'
  desc 'check', 'Interview the application representative and ask for the system documentation that states how often audit logs are reviewed. Also, determine when the audit logs were last reviewed.

If the application representative cannot provide system documentation identifying how often the auditing logs are reviewed, or has not audited within the last time period stated in the system documentation, this is a finding.'
  desc 'fix', 'Establish a scheduled process for reviewing logs.

Maintain a log or records of dates and times audit logs are reviewed.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24292r493774_chk'
  tag severity: 'medium'
  tag gid: 'V-222622'
  tag rid: 'SV-222622r879887_rule'
  tag stig_id: 'APSC-DV-002910'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24281r493775_fix'
  tag 'documentable'
  tag legacy: ['SV-84919', 'V-70297']
  tag cci: ['CCI-001872']
  tag nist: ['AU-6 (10)']
end
