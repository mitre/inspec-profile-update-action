control 'SV-48328' do
  title 'The Enhanced Mitigation Experience Toolkit (EMET) Default Protections for Internet Explorer must be enabled.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications adding additional levels of protection.'
  desc 'check', 'This is applicable to unclassified systems, for other systems this is NA.

If EMET has not been installed and DEP and SEHOP are configured as required in V-68843 and V-68847, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\EMET\\Defaults\\

Value Name: *\\Internet Explorer\\iexplore.exe

Value Type: REG_SZ
Value: +EAF+ eaf_modules:mshtml.dll;flash*.ocx;jscript*.dll;vbscript.dll;vgx.dll +ASR asr_modules:npjpi*.dll;jp2iexp.dll;vgx.dll;msxml4*.dll;wshom.ocx;scrrun.dll;vbscript.dll asr_zones:1;2

Due to a change in the registry structure for EMET 5.5, if the system has a previous version of EMET installed and configured, this setting needs to be set to "Not Configured" prior to the upgrade to EMET 5.5, and the new administrative template files copied to the appropriate area.  The setting can then be re-enabled.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> EMET >> "Default Protections for Internet Explorer" to "Enabled".

Note: The Enhanced Mitigation Experience Toolkit must be installed on the system and the administrative template files added to make this setting available.   

Due to a change in the registry structure for EMET 5.5, if the system has a previous version of EMET installed and configured, this setting needs to be set to "Not Configured" prior to the upgrade to EMET 5.5, and the new administrative template files copied to the appropriate area.  The setting can then be re-enabled.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-67351r4_chk'
  tag severity: 'medium'
  tag gid: 'V-36702'
  tag rid: 'SV-48328r7_rule'
  tag stig_id: 'WN08-CC-000079'
  tag gtitle: 'WINCC-000079'
  tag fix_id: 'F-72801r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
