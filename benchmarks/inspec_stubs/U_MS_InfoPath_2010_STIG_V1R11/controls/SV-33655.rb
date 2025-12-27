control 'SV-33655' do
  title 'Beaconing of UI forms  with ActiveX controls must be enforced.'
  desc 'InfoPath makes it possible to host InfoPath forms in other applications as ActiveX controls. Such controls are known as InfoPath form controls. A malicious user could insert a Web beacon into one of these controls which could be used to contact an external server when the user opens the form. Information could be gathered by the form, or information entered by users could be sent to an external server and cause them to be vulnerable to additional attacks. By default, InfoPath form controls warn users about potential Web beaconing threats.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> Security -> “Beaconing UI for forms opened in InfoPath Filler ActiveX" must be set to “Enabled (Always show beaconing UI)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\infopath\\security

Criteria: If the value EditorActiveXBeaconingUI is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> Security -> “Beaconing UI for forms opened in InfoPath Filler ActiveX" to “Enabled (Always show beaconing UI)”.'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2010'
  tag check_id: 'C-34116r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17746'
  tag rid: 'SV-33655r1_rule'
  tag stig_id: 'DTOO165 - InfoPath'
  tag gtitle: 'DTOO165 - Beaconing UI /forms opened Activex'
  tag fix_id: 'F-29796r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
