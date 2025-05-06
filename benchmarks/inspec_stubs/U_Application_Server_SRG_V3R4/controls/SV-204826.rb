control 'SV-204826' do
  title 'The application server must generate log records when successful/unsuccessful logon attempts occur.'
  desc 'Logging the access to the application server allows the system administrators to monitor user accounts.  By logging successful/unsuccessful logons, the system administrator can determine if an account is compromised (e.g., frequent logons) or is in the process of being compromised (e.g., frequent failed logons) and can take actions to thwart the attack.

Logging successful logons can also be used to determine accounts that are no longer in use.'
  desc 'check', 'Review product documentation and the system configuration to determine if the application server generates log records on successful and unsuccessful logon attempts by users.

If logon attempts do not generate log records, this is a finding.'
  desc 'fix', 'Configure the application server to generate log records when successful/unsuccessful logon attempts are made by users.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4946r283119_chk'
  tag severity: 'medium'
  tag gid: 'V-204826'
  tag rid: 'SV-204826r879874_rule'
  tag stig_id: 'SRG-APP-000503-AS-000228'
  tag gtitle: 'SRG-APP-000503'
  tag fix_id: 'F-4946r283120_fix'
  tag 'documentable'
  tag legacy: ['SV-71715', 'V-57443']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
