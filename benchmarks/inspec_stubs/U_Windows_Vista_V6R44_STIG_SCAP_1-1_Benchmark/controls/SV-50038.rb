control 'SV-50038' do
  title 'The Enhanced Mitigation Experience Toolkit (EMET) Default Protections for Recommended Software must be enabled.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications adding additional levels of protection.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> EMET >> "Default Protections for Recommended Software" to "Enabled".

Note: The Enhanced Mitigation Experience Toolkit must be installed on the system and the administrative template files added to make this setting available.   

Due to a change in the registry structure for EMET 5.5, if the system has a previous version of EMET installed and configured, this setting needs to be set to "Not Configured" prior to the upgrade to EMET 5.5, and the new administrative template files copied to the appropriate area.  The setting can then be re-enabled.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-36703'
  tag rid: 'SV-50038r5_rule'
  tag stig_id: 'WINCC-000080'
  tag gtitle: 'WINCC-000080'
  tag fix_id: 'F-72803r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
