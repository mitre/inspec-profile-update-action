control 'SV-33800' do
  title 'File Downloads must be configured for proper restrictions.'
  desc 'Disabling this setting allows websites to present file download prompts via code without the user specifically initiating the download.  User preferences may also allow the download to occur without prompting or interacting with the user.  Even if Internet Explorer prompts the user to accept the download, some websites abuse this functionality.  Malicious websites may continually prompt users to download a file or present confusing dialog boxes to trick users into downloading or running a file.  If the download occurs and it contains malicious code, the code could become active on user computers or the network.'
  desc 'check', "The policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2010 (Machine) -> Security Settings -> IE Security “Restrict File Download” must be set to “Enabled” and 'outlook.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_FILEDOWNLOAD

Criteria: If the value outlook.exe is REG_DWORD = 1, this is not a finding."
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2010 (Machine) -> Security Settings -> IE Security “Restrict File Download” to “Enabled” and select 'outlook.exe'."
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34174r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26587'
  tag rid: 'SV-33800r1_rule'
  tag stig_id: 'DTOO132 - Outlook'
  tag gtitle: 'DTOO132 - Restrict File Download'
  tag fix_id: 'F-29863r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
