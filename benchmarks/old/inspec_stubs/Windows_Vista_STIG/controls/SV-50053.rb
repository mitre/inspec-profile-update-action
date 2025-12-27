control 'SV-50053' do
  title 'The Enhanced Mitigation Experience Toolkit (EMET) system-wide Data Execution Prevention (DEP) must be enabled and configured to at least Application Opt Out.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications adding additional levels of protection.'
  desc 'fix', 'This is applicable to unclassified systems, for other systems this is NA.

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> EMET -> "System DEP" to "Enabled" with at least "Application Opt-Out" selected. 

The Enhanced Mitigation Experience Toolkit must be installed on the system and the administrative template files added to make this setting available.

Document applications that do not function properly due to this setting, and are opted out, with the ISSO.

Opted out exceptions can be configured with the following command:
EMET_Conf --Set "application path\\executable name" -DEP

Alternately, configure exceptions in System Properties:
Select "System" in Control Panel.
Select "Advanced system settings".
Click "Settings" in the "Performance" section.
Select the "Data Execution Prevention" tab.
Select "Turn on DEP for all programs and services except those I select:".

Applications that are opted out are configured in the window below this selection.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-36705'
  tag rid: 'SV-50053r5_rule'
  tag stig_id: 'WINCC-000082'
  tag gtitle: 'WINCC-000082'
  tag fix_id: 'F-49744r5_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
