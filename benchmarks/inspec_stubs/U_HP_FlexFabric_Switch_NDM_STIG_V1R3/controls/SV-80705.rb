control 'SV-80705' do
  title 'The HP FlexFabric Switch must enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement.

Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy-based intervals; however, if the HP FlexFabric Switch allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'Determine if the HP FlexFabric Switch enforces 24 hours/1 day as the minimum password lifetime.

[HP] display password-control

Global password control configurations:
 Password control:                    Enabled
 Password aging:                      Enabled (90 days)
 Password length:                     Enabled (15 characters)
 Password composition:                Enabled (1 types, 1 characters per type)
 Password history:                    Enabled (max history records: 4)
 Early notice on password expiration: 7 days
 Maximum login attempts:              3
 Action for exceeding login attempts: Lock user for 1 minutes
 Minimum interval between two updates: 24 hours

If the HP FlexFabric Switch or its associated authentication server does not enforce 24 hours/1 day as the minimum password lifetime, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to enforce 24 hours/1 day as the minimum password lifetime.

[HP] password-control enable
[HP] password-control update-interval 24'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66861r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66215'
  tag rid: 'SV-80705r1_rule'
  tag stig_id: 'HFFS-ND-000062'
  tag gtitle: 'SRG-APP-000173-NDM-000260'
  tag fix_id: 'F-72291r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
