control 'SV-95129' do
  title 'The Bromium Enterprise Controller (BEC) lockout_delay_base in the settings.json file must be set to a minimum of 10 and the lockout_delay_scale must be set to 1 at a minimum.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Navigate to C:\\ProgramData\\Bromium\\BMS\\settings.json on the BEC. Verify the value of  lockout_delay_base is set to "10" and the lockout_delay_scale is set to "1" at a minimum.

If the BEC lockout_delay_base in the settings.json file is not set to a minimum of "10" and the lockout_delay_scale is not set to a minimum of "1", this is a finding.'
  desc 'fix', 'Edit the BEC configuration file (C:\\ProgramData\\Bromium\\BMS\\settings.json) to set lockout_delay_base to "10" and the lockout_delay_scale to "1" at a minimum.'
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80097r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80425'
  tag rid: 'SV-95129r1_rule'
  tag stig_id: 'BROM-00-000100'
  tag gtitle: 'SRG-APP-000065'
  tag fix_id: 'F-87231r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
