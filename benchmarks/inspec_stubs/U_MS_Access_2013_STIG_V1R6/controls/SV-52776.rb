control 'SV-52776' do
  title 'Trust access for VBA must be disallowed.'
  desc 'VSTO projects require access to the Visual Basic for Applications project system in Excel, PowerPoint, and Word, even though the projects do not use Visual Basic for Applications. Design-time support of controls in both Visual Basic and C# projects depends on the Visual Basic for Applications project system in Word and Excel. By default, Excel, Word, and PowerPoint do not allow automation clients to have programmatic access to VBA projects. Users can enable this by selecting the Trust access to the VBA project object model in the Macro Settings section of the Trust Center. However, doing so allows macros in any documents the user opens to access the core Visual Basic objects, methods, and properties, which represents a potential security hazard.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2013 -> Application Settings -> Security ->  Trust Center -> "VBA macro Notification Settings" is set to "Enabled: Disable all with notification".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\15.0\\access\\security

Criteria: If the value vbawarnings is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration -> Administrative Templates -> Microsoft Access 2013 -> Application Settings -> Security ->  Trust Center -> "VBA macro Notification Settings" must be set to "Enabled: Disable all with notification".'
  impact 0.5
  ref 'DPMS Target Microsoft Access 2013'
  tag check_id: 'C-47105r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17545'
  tag rid: 'SV-52776r1_rule'
  tag stig_id: 'DTOO304'
  tag gtitle: 'DTOO304 - VBA Macro Warning settings'
  tag fix_id: 'F-45702r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
