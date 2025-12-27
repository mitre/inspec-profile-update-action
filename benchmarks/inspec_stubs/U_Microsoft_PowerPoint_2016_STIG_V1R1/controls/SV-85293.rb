control 'SV-85293' do
  title 'Trust access for VBA must be disallowed.'
  desc 'This policy setting controls whether automation clients such as Microsoft Visual Studio 2005 Tools for Microsoft Office (VSTO) can access the Visual Basic for Applications project system in the specified applications. VSTO projects require access to the Visual Basic for Applications project system in Excel, PowerPoint, and Word, even though the projects do not use Visual Basic for Applications. Design-time support of controls in both Visual Basic and C# projects depends on the Visual Basic for Applications project system in Word and Excel. If you enable this policy setting, VSTO and other automation clients can access the Visual Basic for Applications project system in the specified applications. Users will not be able to change this behavior through the "Trust access to the VBA project object model" user interface option under the Macro Settings section of the Trust Center. If you disable this policy setting, VSTO does not have programmatic access to VBA projects. In addition, the "Trust access to the VBA project object model" check box is cleared and users cannot change it.  Note: Disabling this policy setting prevents VSTO projects from interacting properly with the VBA project system in the selected application. If you do not configure this policy setting, automation clients do not have programmatic access to VBA projects. Users can enable this by selecting the "Trust access to the VBA project object model" in the "Macro Settings" section of the Trust Center. However, doing so allows macros in any documents the user opens to access the core Visual Basic objects, methods, and properties, which represents a potential security hazard.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2016 -> PowerPoint Options -> Security -> Trust Center "Trust access to Visual Basic Project" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\PowerPoint\\security

Criteria: If the value AccessVBOM is REG_DWORD=0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2016 -> PowerPoint Options -> Security -> Trust Center "Trust access to Visual Basic Project" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2016'
  tag check_id: 'C-71071r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70671'
  tag rid: 'SV-85293r1_rule'
  tag stig_id: 'DTOO146'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-76915r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
