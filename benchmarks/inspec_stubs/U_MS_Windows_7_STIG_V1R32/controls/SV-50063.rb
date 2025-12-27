control 'SV-50063' do
  title 'The Enhanced Mitigation Experience Toolkit (EMET) system-wide Structured Exception Handler Overwrite Protection (SEHOP) must be configured to Application Opt Out.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications adding additional levels of protection.'
  desc 'check', 'This is applicable to unclassified systems, for other systems this is NA.

If EMET has not been installed and DEP and SEHOP are configured as required in V-68843 and V-68847, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\EMET\\SysSettings\\

Value Name:  SEHOP

Type:  REG_DWORD
Value:  2

Applications that do not function properly due to this setting, and are opted out, must be documented with the ISSO.'
  desc 'fix', 'This is applicable to unclassified systems, for other systems this is NA.

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> EMET -> "System SEHOP" to "Enabled" with "Application Opt-Out" selected.

The Enhanced Mitigation Experience Toolkit must be installed on the system and the administrative template files added to make this setting available.

Document applications that do not function properly due to this setting, and are opted out, with the ISSO.

Opted out exceptions can be configured with the following command:
EMET_Conf --Set "application path\\executable name" -SEHOP'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-45819r8_chk'
  tag severity: 'medium'
  tag gid: 'V-36706'
  tag rid: 'SV-50063r6_rule'
  tag stig_id: 'WINCC-000083'
  tag gtitle: 'WINCC-000083'
  tag fix_id: 'F-49750r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
