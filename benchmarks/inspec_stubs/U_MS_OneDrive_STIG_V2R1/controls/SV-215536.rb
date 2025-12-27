control 'SV-215536' do
  title 'File Downloads must be configured for proper restrictions.'
  desc 'Disabling this setting allows websites to present file download prompts via code without the user specifically initiating the download. User preferences may also allow the download to occur without prompting or interaction with the user. Even if Internet Explorer prompts the user to accept the download, some websites abuse this functionality. Malicious websites may continually prompt users to download a file or present confusing dialog boxes to trick users into downloading or running a file. If the download occurs and it contains malicious code, the code could become active on user computers or the network.'
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Restrict File Download" is set to "Enabled" and 'groove.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD

Criteria: If the value of groove.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Restrict File Download" to "Enabled" and place a check in the 'groove.exe' check box.)
  impact 0.5
  ref 'DPMS Target Microsoft OneDrive'
  tag check_id: 'C-16731r312226_chk'
  tag severity: 'medium'
  tag gid: 'V-215536'
  tag rid: 'SV-215536r569322_rule'
  tag stig_id: 'DTOO132'
  tag gtitle: 'SRG-APP-000209'
  tag fix_id: 'F-16729r312227_fix'
  tag 'documentable'
  tag legacy: ['SV-85941', 'V-71317']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
