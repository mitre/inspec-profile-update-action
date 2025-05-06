control 'SV-223294' do
  title 'Office applications must not load XML expansion packs with Smart Documents.'
  desc 'This policy setting controls whether Office 365 ProPlus applications can load an XML expansion pack manifest file with a Smart Document.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Smart Documents (Word, Excel) >> Disable Smart Document's use of manifests is set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\software\policies\microsoft\office\common\smart tag

If the value for neverloadmanifests is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Smart Documents (Word, Excel) >> Disable Smart Document's use of manifests to "Enabled".)
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24967r442101_chk'
  tag severity: 'medium'
  tag gid: 'V-223294'
  tag rid: 'SV-223294r508019_rule'
  tag stig_id: 'O365-CO-000012'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24955r442102_fix'
  tag 'documentable'
  tag legacy: ['SV-108767', 'V-99663']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
