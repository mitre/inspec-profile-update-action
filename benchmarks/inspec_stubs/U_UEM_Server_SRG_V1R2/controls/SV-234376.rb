control 'SV-234376' do
  title 'The UEM server must enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement.

Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy based intervals; however, if the application allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse. 

Satisfies:FMT_SMF.1(2)b 
Reference:PP-MDM-431023"
  desc 'check', 'Verify the UEM server enforces 24 hours/1 day as the minimum password lifetime.

If the UEM server does not enforce 24 hours/1 day as the minimum password lifetime, this is a finding.'
  desc 'fix', 'Configure the UEM server to enforce 24 hours/1 day as the minimum password lifetime.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37561r614138_chk'
  tag severity: 'medium'
  tag gid: 'V-234376'
  tag rid: 'SV-234376r879610_rule'
  tag stig_id: 'SRG-APP-000173-UEM-000103'
  tag gtitle: 'SRG-APP-000173'
  tag fix_id: 'F-37526r614139_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
