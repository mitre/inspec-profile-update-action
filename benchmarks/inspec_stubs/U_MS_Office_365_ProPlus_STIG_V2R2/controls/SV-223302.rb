control 'SV-223302' do
  title 'Navigate URL must be enabled in all Office programs.'
  desc 'To protect users from attacks, Internet Explorer usually does not attempt to load malformed URLs. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a web page). If Internet Explorer attempts to load a malformed URL, a security risk could occur.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >> Navigate URL is set to "Enabled" and the check box is selected for every installed Office program.

Use the Windows Registry Editor to navigate to the following key:

HKLM\\software\\microsoft\\internet explorer\\main\\featurecontrol\\feature_validate_navigate_url

If the value for all installed programs is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >> Navigate URL to "Enabled" and select the check boxes for all installed Office programs.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24975r442125_chk'
  tag severity: 'medium'
  tag gid: 'V-223302'
  tag rid: 'SV-223302r508019_rule'
  tag stig_id: 'O365-CO-000020'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-24963r442126_fix'
  tag 'documentable'
  tag legacy: ['SV-108783', 'V-99679']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
