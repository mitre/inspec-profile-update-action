control 'SV-95127' do
  title 'The Bromium Enterprise Controller (BEC) must set the number of concurrent sessions to 1.'
  desc 'Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to denial-of-service (DoS) attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system.

Edit the BEC configuration file (C:\\ProgramData\\Bromium\\BMS\\settings.json) to set the concurrent session parameter. The options are "unlimited" and "1". Unlimited is not a valid selection in DoD.'
  desc 'check', 'Inspect the configuration file on the BEC.  BEC configuration file (C:\\ProgramData\\Bromium\\BMS\\settings.json). Verify the concurrent session parameter is set to "1".

If the BEC concurrent session parameter is not set to "1", this is a finding.'
  desc 'fix', 'Edit the BEC configuration file (C:\\ProgramData\\Bromium\\BMS\\settings.json) to set the concurrent session parameter to "1".'
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80095r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80423'
  tag rid: 'SV-95127r1_rule'
  tag stig_id: 'BROM-00-000005'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-87229r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
