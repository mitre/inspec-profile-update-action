control 'SV-33398' do
  title 'Links that invoke instances of IE from within an Office product must be blocked.'
  desc 'The Pop-up Blocker feature in Internet Explorer can be used to block most unwanted pop-up and pop-under windows from appearing. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a Web page). If the Pop-up Blocker is disabled, disruptive and potentially dangerous pop-up windows could load and present a security risk.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2010 (Machine) -> Security Settings -> IE Security “Block popups” must be “Enabled” and ‘outlook.exe’ is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_WEBOC_POPUPMANAGEMENT

Criteria: If the value outlook.exe is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2010 (Machine) -> Security Settings -> IE Security “Block popups” to “Enabled” and select ‘outlook.exe’.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17184'
  tag rid: 'SV-33398r1_rule'
  tag stig_id: 'DTOO129 - Outlook'
  tag gtitle: 'DTOO129 - Block Pop-Ups'
  tag fix_id: 'F-29570r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
