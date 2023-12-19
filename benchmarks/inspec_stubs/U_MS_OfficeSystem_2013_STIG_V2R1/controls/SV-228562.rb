control 'SV-228562' do
  title 'Office automatic updates must be enabled for Office products installed via Click-to-Run and configured to use a Trusted site.'
  desc 'This policy setting controls whether the Office automatic updates are enabled or disabled for all Office products installed via Click-to-Run. This policy has no effect on Office products installed via Windows Installer. If this policy setting is enabled, Office periodically checks for updates. When updates are detected, Office downloads and applies them in the background. If policy setting is disabled, Office will not check for updates. Without receiving automatic updates, vulnerabilities found within the Office products will not be applied, leaving the vulnerabilities exposed.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine)->Updates->"Enable Automatic Updates" is set to "Enabled".
Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Updates -> "Specify intranet Microsoft update service location" is set to "Enabled" and the "Set the intranet update service for detecting updates:" and the "Set the intranet statistics server:" both point to an Intranet system.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\software\\policies\\Microsoft\\office\\15.0\\common\\officeupdate
Criteria: If the value EnableAutomaticUpdates is REG_DWORD = 1, this is not a finding.
If the registry key is missing, this is an Open finding. This setting is, by default, enabled and must be explicitly configured to be disabled.
HKLM\\software\\policies\\Microsoft\\Windows\\WindowsUpdate
Criteria: If the value of WUServer and WUStatusServer are populated with an Intranet system, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine)->Updates->"Enable Automatic Updates" to "Enabled".

Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Updates -> "Specify intranet Microsoft update service location" to "Enabled" and the "Set the intranet update service for detecting updates:" and the "Set the intranet statistics server:"to point to an Intranet system.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30795r498964_chk'
  tag severity: 'medium'
  tag gid: 'V-228562'
  tag rid: 'SV-228562r508020_rule'
  tag stig_id: 'DTOO401'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-30780r498971_fix'
  tag 'documentable'
  tag legacy: ['SV-53190', 'V-40858']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
