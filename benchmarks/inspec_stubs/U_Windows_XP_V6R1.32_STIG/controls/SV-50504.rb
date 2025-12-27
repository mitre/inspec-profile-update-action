control 'SV-50504' do
  title 'The Enhanced Mitigation Experience Toolkit (EMET) system-wide Data Execution Prevention (DEP) must be enabled and configured to at least Application Opt Out.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP) on the system and applications adding additional levels of protection.'
  desc 'check', 'Open EMET in Programs\\Enhanced Mitigation Experience Toolkit.
Verify under System Status that Data Execution Prevention (DEP) is configured to "Application Opt Out".

Alternately verify in System Properties.
Select "System" in Control Panel.
Select the "Advanced" tab.
Click "Settings" in the "Performance" section.
Select the "Data Execution Prevention" tab.
Verify "Turn on DEP for all programs and services except those I select:" is selected.

If DEP is not configured as specified, this is a finding.

Applications that do not function properly due to this setting, and are opted out, must be documented with the IAO.'
  desc 'fix', 'Open EMET in Programs\\Enhanced Mitigation Experience Toolkit.
Configure Data Execution Prevention (DEP) under System Status to "Application Opt Out".

The Enhanced Mitigation Experience Toolkit must be installed on the system to make this setting available.

Document applications that do not function properly due to this setting, and are opted out, with the IAO.

Alternately configure in System Properties.
Select "System" in Control Panel.
Select the "Advanced" tab.
Click "Settings" in the "Performance" section.
Select the "Data Execution Prevention" tab.
Select "Turn on DEP for all programs and services except those I select:".

Applications that are opted out are configured in the window below this selection.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-46265r5_chk'
  tag severity: 'medium'
  tag gid: 'V-36705'
  tag rid: 'SV-50504r2_rule'
  tag stig_id: 'WINEM-000082'
  tag gtitle: 'WINCC-000082'
  tag fix_id: 'F-43652r3_fix'
  tag 'documentable'
  tag ia_controls: 'ECVP-1'
end
