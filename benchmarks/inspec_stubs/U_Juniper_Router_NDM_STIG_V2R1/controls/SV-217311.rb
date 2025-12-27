control 'SV-217311' do
  title 'The Juniper router must be configured to enforce the limit of three consecutive invalid logon attempts after which time lock out the user account from accessing the device for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Review the router configuration to verify that it enforces the limit of three consecutive invalid logon attempts after which time it will lockout the user account from accessing the router for 15 minutes as shown in the example below.

    login {
        retry-options {
            tries-before-disconnect 3;
            lockout-period 15;
        }

If the router is not configured to enforce the limit of three consecutive invalid logon attempts after which time it will lockout the user account from accessing the router for 15 minutes, this is a finding.'
  desc 'fix', 'Configure the router to enforce the limit of three consecutive invalid logon attempts and lock out the user account from accessing the device for 15 minutes as shown in the example below.

[edit system login]
set retry-options tries-before-disconnect 3
set retry-options lockout-period 15'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18538r296511_chk'
  tag severity: 'medium'
  tag gid: 'V-217311'
  tag rid: 'SV-217311r395607_rule'
  tag stig_id: 'JUNI-ND-000150'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-18536r296512_fix'
  tag 'documentable'
  tag legacy: ['SV-101205', 'V-91105']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
