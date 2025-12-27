control 'SV-33652' do
  title 'Beaconing UI shown for opened forms must be configured.'
  desc 'Malicious users can create InfoPath forms with embedded Web beacons that can be used to contact an external server when the user opens the form. Information could be gathered by the form, or information entered by users could be sent to an external server and cause them to be vulnerable to additional attacks. By default, InfoPath warns users about potential Web beaconing threats.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> Security -> “Beaconing UI for forms opened in InfoPath” must be set to “Enabled (Always show beaconing UI)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\infopath\\security

Criteria: If the value InfoPathBeaconingUI is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> Security -> “Beaconing UI for forms opened in InfoPath” to “Enabled (Always show beaconing UI)”.'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2010'
  tag check_id: 'C-34113r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17745'
  tag rid: 'SV-33652r1_rule'
  tag stig_id: 'DTOO164 - InfoPath'
  tag gtitle: 'DTOO164 - Beaconing UI / forms opening'
  tag fix_id: 'F-29793r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
