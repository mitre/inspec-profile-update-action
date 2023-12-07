control 'SV-50043' do
  title 'The Enhanced Mitigation Experience Toolkit (EMET) Default Protections for Recommended Software must be enabled.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications adding additional levels of protection.'
  desc 'check', 'This is applicable to unclassified systems, for other systems this is NA.

If EMET has not been installed and DEP and SEHOP are configured as required in V-68843 and V-68847, this is NA.

If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\EMET\\Defaults\\
Value Type: REG_SZ (for each Value below)

Values noted as "Blank" are empty in the registry.

Value Name: *\\Adobe\\*\\Reader\\AcroRd32.exe
Value: +EAF+ eaf_modules:AcroRd32.dll;Acrofx32.dll;AcroForm.api

Value Name: *\\Adobe\\Acrobat*\\Acrobat\\Acrobat.exe
Value: +EAF+ eaf_modules:AcroRd32.dll;Acrofx32.dll;AcroForm.api

Value Name: *\\Java\\jre*\\bin\\java.exe
Value: -HeapSpray

Value Name: *\\Java\\jre*\\bin\\javaw.exe
Value: -HeapSpray

Value Name: *\\Java\\jre*\\bin\\javaws.exe
Value: -HeapSpray

Value Name: *\\OFFICE1*\\EXCEL.EXE
Value: +ASR asr_modules:flash*.ocx

Value Name: *\\OFFICE1*\\INFOPATH.EXE
Value: "Blank"

Value Name: *\\OFFICE1*\\LYNC.EXE
Value: "Blank"

Value Name: *\\OFFICE1*\\MSACCESS.EXE
Value: "Blank"

Value Name: *\\OFFICE1*\\MSPUB.EXE
Value: "Blank"

Value Name: *\\OFFICE1*\\OIS.EXE
Value: "Blank"

Value Name: *\\OFFICE1*\\OUTLOOK.EXE
Value: "Blank"

Value Name: *\\OFFICE1*\\POWERPNT.EXE
Value: +ASR asr_modules:flash*.ocx

Value Name: *\\OFFICE1*\\PPTVIEW.EXE
Value: "Blank"

Value Name: *\\OFFICE1*\\VISIO.EXE
Value: "Blank"

Value Name: *\\OFFICE1*\\VPREVIEW.EXE
Value: "Blank"

Value Name: *\\OFFICE1*\\WINWORD.EXE
Value: +ASR asr_modules:flash*.ocx

Value Name: *\\Windows NT\\Accessories\\wordpad.exe
Value: "Blank"

Due to a change in the registry structure for EMET 5.5, if the system has a previous version of EMET installed and configured, this setting needs to be set to "Not Configured" prior to the upgrade to EMET 5.5, and the new administrative template files copied to the appropriate area.  The setting can then be re-enabled.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> EMET >> "Default Protections for Recommended Software" to "Enabled".

Note: The Enhanced Mitigation Experience Toolkit must be installed on the system and the administrative template files added to make this setting available.   

Due to a change in the registry structure for EMET 5.5, if the system has a previous version of EMET installed and configured, this setting needs to be set to "Not Configured" prior to the upgrade to EMET 5.5, and the new administrative template files copied to the appropriate area.  The setting can then be re-enabled.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-67355r3_chk'
  tag severity: 'medium'
  tag gid: 'V-36703'
  tag rid: 'SV-50043r6_rule'
  tag stig_id: 'WINCC-000080'
  tag gtitle: 'WINCC-000080'
  tag fix_id: 'F-72805r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
