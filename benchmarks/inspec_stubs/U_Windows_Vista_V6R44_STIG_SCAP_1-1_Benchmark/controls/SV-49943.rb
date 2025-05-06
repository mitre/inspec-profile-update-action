control 'SV-49943' do
  title 'The Enhanced Mitigation Experience Toolkit (EMET) system-wide Address Space Layout Randomization (ASLR) must be enabled and configured to Application Opt In.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications adding additional levels of protection.'
  desc 'fix', 'This is applicable to unclassified systems, for other systems this is NA.

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> EMET -> "System ASLR" to "Enabled" with "Application Opt-In" selected.

The Enhanced Mitigation Experience Toolkit must be installed on the system and the administrative template files added to make this setting available.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-36701'
  tag rid: 'SV-49943r5_rule'
  tag stig_id: 'WINCC-000078'
  tag gtitle: 'WINCC-000078'
  tag fix_id: 'F-49714r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
