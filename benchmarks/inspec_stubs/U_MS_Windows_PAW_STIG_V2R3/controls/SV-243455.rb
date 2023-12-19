control 'SV-243455' do
  title 'PAWs used to manage Active Directory must only allow groups specifically designated to manage Active Directory, such as Enterprise and Domain Admins and members of the local Administrators group, to log on locally.'
  desc 'PAW platforms are used for highly privileged activities. The accounts that have administrative privileges on domain-level PAW platforms must not be used on or used to manage any non-domain-level PAW platforms. Otherwise, there would be a clear path for privilege escalation to Enterprise Admin (EA)/Domain Admin (DA) privileges.'
  desc 'check', 'Verify on the PAW the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Allow log on locally" user right, this is a finding:

- Administrators
- Groups specifically designated to manage domain controllers and Active Directory'
  desc 'fix', 'Configure the group policy that applies to the PAW.

Install only administrative accounts designated to be used to manage domain controllers and Active Directory remotely in the PAW User group on PAWs designated for the management of domain controllers and Active Directory.

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Allow log on locally" to only include the following groups or accounts:

- Administrators
- Groups specifically designated to manage domain controllers and Active Directory'
  impact 0.5
  ref 'DPMS Target Microsoft Windows PAW'
  tag check_id: 'C-46730r722934_chk'
  tag severity: 'medium'
  tag gid: 'V-243455'
  tag rid: 'SV-243455r722936_rule'
  tag stig_id: 'WPAW-00-001400'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-46687r722935_fix'
  tag 'documentable'
  tag legacy: ['V-78171', 'SV-92877']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
