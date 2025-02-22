control 'SV-243457' do
  title 'The Windows PAW must be configured to enforce two-factor authentication and use Active Directory for authentication management.'
  desc 'Due to the highly privileged functions of a PAW, a high level of trust must be implemented for access to the PAW, including non-repudiation of the user session. One-factor authentication, including username and password and shared administrator accounts, does not provide adequate assurance.'
  desc 'check', 'Review the configuration on the PAW.

Verify group policy is configured to enable either smart card or another DoD-approved two-factor authentication method for site PAWs.

- In Active Directory, go to Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\Security Options.
- Verify "Interactive logon: Require smart card" is set to "Enabled".

If group policy is not configured to enable either smart card or another DoD-approved two-factor authentication method, this is a finding.'
  desc 'fix', 'In Active Directory, configure group policy to enable either smart card or another DoD-approved two-factor authentication method for all PAWs.

- Go to Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\Security Options.
- Set "Interactive logon: Require smart card" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows PAW'
  tag check_id: 'C-46732r722940_chk'
  tag severity: 'medium'
  tag gid: 'V-243457'
  tag rid: 'SV-243457r722942_rule'
  tag stig_id: 'WPAW-00-001600'
  tag gtitle: 'SRG-OS-000107-GPOS-00054'
  tag fix_id: 'F-46689r722941_fix'
  tag 'documentable'
  tag legacy: ['V-78175', 'SV-92881']
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
