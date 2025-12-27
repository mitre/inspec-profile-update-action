control 'SV-228532' do
  title 'Online content options must be configured for offline content availability.'
  desc "The Office 2013 Help system automatically searches MicrosoftOffice.com for content when a computer is connected to the Internet. Users can change this default by clearing the Search Microsoft Office.com for Help content when I'm connected to the Internet check box in the Privacy Options section of the Trust Center. If an organization has policies that govern the use of external resources such as Office.com, allowing the Help system to download content might cause users to violate these policies."
  desc 'check', %q(Note: This check is Not Applicable when the use of Office 365 is against the specific DoD instance of O365.

The use of Offline Content for Non-DoD instances of O365 is prohibited and it must not allow for personal account synchronization.

All non-DoD instances are subject to this requirement.

Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Tools >> Options >> General >> Service Options... >> Online Content "Online content options" is set to "Enabled: Do not allow Office to connect to the internet".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\internet

If the value 'UseOnlineContent' is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Tools >> Options >> General >> Service Options... >> Online Content "Online content options" to "Enabled: Do not allow Office to connect to the internet".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30765r498874_chk'
  tag severity: 'medium'
  tag gid: 'V-228532'
  tag rid: 'SV-228532r508020_rule'
  tag stig_id: 'DTOO345'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30750r498875_fix'
  tag 'documentable'
  tag legacy: ['V-26630', 'SV-52758']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
