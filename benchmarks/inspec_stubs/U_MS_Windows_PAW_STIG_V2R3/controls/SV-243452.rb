control 'SV-243452' do
  title 'Windows PAWs must be restricted to only allow groups used to manage high-value IT resources and members of the local Administrators group to log on locally.'
  desc 'A main security architectural construct of a PAW is to limit users of the PAW to only administrators of high-value IT resources. This will mitigate some of the risk of attack on administrators of high-value IT resources.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Allow log on locally" user right, this is a finding:

- Administrators
- Groups specifically designated to manage high-value IT resources'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Allow log on locally" to only include the following groups or accounts:

- Administrators
- Groups specifically designated to manage high-value IT resources'
  impact 0.5
  ref 'DPMS Target Microsoft Windows PAW'
  tag check_id: 'C-46727r722925_chk'
  tag severity: 'medium'
  tag gid: 'V-243452'
  tag rid: 'SV-243452r722927_rule'
  tag stig_id: 'WPAW-00-001100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-46684r722926_fix'
  tag 'documentable'
  tag legacy: ['V-78165', 'SV-92871']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
