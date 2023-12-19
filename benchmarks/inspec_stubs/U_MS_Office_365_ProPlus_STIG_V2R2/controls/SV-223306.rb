control 'SV-223306' do
  title 'File Download Restriction must be enabled in all Office programs.'
  desc 'Disabling this setting allows websites to present file download prompts via code without the user specifically initiating the download. User preferences may also allow the download to occur without prompting or interaction with the user. Even if Internet Explorer prompts the user to accept the download, some websites abuse this functionality. Malicious websites may continually prompt users to download a file or present confusing dialog boxes to trick users into downloading or running a file. If the download occurs and it contains malicious code, the code could become active on user computers or the network.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >> Restrict File Download is set to "Enabled" and the check box is selected for every installed Office program.

Use the Windows Registry Editor to navigate to the following key:

HKLM\\software\\microsoft\\internet explorer\\main\\featurecontrol\\feature_restrict_filedownload

If the value for all installed programs is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >> Restrict File Download to "Enabled" and select the check boxes for  all installed Office programs.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24979r442137_chk'
  tag severity: 'medium'
  tag gid: 'V-223306'
  tag rid: 'SV-223306r508019_rule'
  tag stig_id: 'O365-CO-000024'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-24967r442138_fix'
  tag 'documentable'
  tag legacy: ['SV-108791', 'V-99687']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
