control 'SV-228553' do
  title 'Users must be prevented from using or inserting apps that come from the Office Store.'
  desc 'This policy setting allows users to be prevented from using or inserting apps that come from the Office Store. If this policy setting is enabled, apps from the Office Store are blocked. If this policy setting is disabled or not configured, apps from the Office Store are allowed, unless the "Block Apps for Office" policy setting is enabled.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings >> Trust Center >> Trusted Catalogs "Block the Office Store" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\wef\trustedcatalogs

If the value 'disableomexcatalogs' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings >> Trust Center >> Trusted Catalogs "Block the Office Store" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30786r498937_chk'
  tag severity: 'medium'
  tag gid: 'V-228553'
  tag rid: 'SV-228553r508020_rule'
  tag stig_id: 'DTOO413'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-30771r498938_fix'
  tag 'documentable'
  tag legacy: ['V-40883', 'SV-53215']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
