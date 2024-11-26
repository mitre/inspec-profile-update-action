control 'SV-233097' do
  title 'The container platform must enforce 24 hours (one day) as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement.

Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy-based intervals; however, if the application allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'Review the container platform configuration to determine if it enforces 24 hours/1 day as the minimum password lifetime. 

If the container platform does not enforce 24 hours/1 day as the minimum password lifetime, this is a finding.'
  desc 'fix', 'Configure the container platform to enforce 24 hours/1 day as the minimum password lifetime.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36033r600778_chk'
  tag severity: 'medium'
  tag gid: 'V-233097'
  tag rid: 'SV-233097r879610_rule'
  tag stig_id: 'SRG-APP-000173-CTR-000445'
  tag gtitle: 'SRG-APP-000173'
  tag fix_id: 'F-36001r600779_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
