control 'SV-215535' do
  title 'Links that invoke instances of Internet Explorer from within an Office product must be blocked.'
  desc 'The Pop-up Blocker feature in Internet Explorer can be used to block most unwanted pop-up and pop-under windows from appearing. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a web page). If the Pop-up Blocker is disabled, disruptive and potentially dangerous pop-up windows could load and present a security risk.'
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Block popups" is set to "Enabled" and 'groove.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT

Criteria: If the value groove.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Block popups" to "Enabled" and place a check in the 'groove.exe' check box.)
  impact 0.5
  ref 'DPMS Target Microsoft OneDrive for Business 2016'
  tag check_id: 'C-16730r312223_chk'
  tag severity: 'medium'
  tag gid: 'V-215535'
  tag rid: 'SV-215535r569322_rule'
  tag stig_id: 'DTOO129'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-16728r312224_fix'
  tag 'documentable'
  tag legacy: ['SV-85937', 'V-71313']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
