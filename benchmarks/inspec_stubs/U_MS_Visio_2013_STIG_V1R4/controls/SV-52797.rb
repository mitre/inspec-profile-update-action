control 'SV-52797' do
  title 'File downloads must be configured for proper restrictions.'
  desc 'Disabling this setting allows websites to present file download prompts via code without the user specifically initiating the download. User preferences may also allow the download to occur without prompting or interaction with the user. Even if Internet Explorer prompts the user to accept the download, some websites abuse this functionality. Malicious websites may continually prompt users to download a file or present confusing dialog boxes to trick users into downloading or running a file. If the download occurs and it contains malicious code, the code could become active on user computers or the network.'
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Restrict File Download" is set to "Enabled" and 'Visio.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD

Criteria: If the value visio.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Restrict File Download" to "Enabled" and 'visio.exe' is checked.)
  impact 0.5
  ref 'DPMS Target Microsoft Visio 2013'
  tag check_id: 'C-47126r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40739'
  tag rid: 'SV-52797r1_rule'
  tag stig_id: 'DTOO132'
  tag gtitle: 'DTOO132 - Restrict File Download'
  tag fix_id: 'F-45723r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
