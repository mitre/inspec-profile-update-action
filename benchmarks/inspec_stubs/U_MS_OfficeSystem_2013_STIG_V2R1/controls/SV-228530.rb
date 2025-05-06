control 'SV-228530' do
  title 'Automatic receiving of small updates to improve reliability must be disallowed.'
  desc 'Having access to updates, add-ins, and patches on the Office Online website can help users ensure computers are up to date and equipped with the latest security patches. However, to ensure updates are tested and applied in a consistent manner, many organizations prefer to roll out updates using a centralized mechanism such as Microsoft Systems Center or Windows Server Update Services.
By default, users are allowed to download updates, add-ins, and patches from the Office Online Web site to keep their Office applications running smoothly and securely. If an organization has policies that govern the use of external resources such as Office Online, allowing users to download updates might cause them to violate these policies.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Privacy >> Trust Center "Automatically receive small updates to improve reliability" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common

If the value 'UpdateReliabilityData' is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Privacy -> Trust Center "Automatically receive small updates to improve reliability" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30763r498868_chk'
  tag severity: 'medium'
  tag gid: 'V-228530'
  tag rid: 'SV-228530r508020_rule'
  tag stig_id: 'DTOO185'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30748r498869_fix'
  tag 'documentable'
  tag legacy: ['SV-52722', 'V-17740']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
