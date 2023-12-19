control 'SV-54949' do
  title 'File Links that invoke instances of Internet Explorer from within an Office product must be blocked in PowerPoint Viewer.'
  desc 'The Pop-up Blocker feature in Internet Explorer can be used to block most unwanted pop-up and pop-under windows from appearing. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a web page). If the Pop-up Blocker is disabled, disruptive and potentially dangerous pop-up windows could load and present a security risk.'
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Block popups" must be "Enabled" and 'pptview.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT

Criteria: If the value pptview.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Block popups" to "Enabled" and select 'pptview.exe'.)
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2013'
  tag check_id: 'C-48708r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42330'
  tag rid: 'SV-54949r1_rule'
  tag stig_id: 'DTOO507'
  tag gtitle: 'DTOO507 - Block Pop-Ups in PowerPoint Viewer'
  tag fix_id: 'F-47829r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
