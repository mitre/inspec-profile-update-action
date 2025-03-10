control 'SV-223296' do
  title 'Add-on Management must be enabled for all Office 365 ProPlus programs.'
  desc "Internet Explorer add-ons are pieces of code, run in Internet Explorer, to provide additional functionality. Rogue add-ons may contain viruses or other malicious code. Disabling or not configuring this setting could allow malicious code or users to become active on user computers or the network. For example, a malicious user can monitor and then use keystrokes that user's type into Internet Explorer. Even legitimate add-ons may demand resources, compromising the performance of Internet Explorer and the operating systems for user computers."
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security "Add-on Management" is set to "Enabled" and the check box is selected for every installed Office program.

Use the Windows Registry Editor to navigate to the following key:

HKLM\\Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_ADDON_MANAGEMENT

If the value for each installed Office Program is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security "Add-on Management" to "Enabled" and select the check boxes for  all installed Office programs.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24969r442107_chk'
  tag severity: 'medium'
  tag gid: 'V-223296'
  tag rid: 'SV-223296r508019_rule'
  tag stig_id: 'O365-CO-000014'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-24957r442108_fix'
  tag 'documentable'
  tag legacy: ['SV-108771', 'V-99667']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
