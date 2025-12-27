control 'SV-53384' do
  title 'Email with InfoPath forms must be configured to show UI to recipients.'
  desc "Malicious users could send InfoPath email forms with embedded web beacons that can be used to track when recipients open the form and provide confirmation that recipients' email addresses are valid. Additional information gathered by the form or information entered by users could also be sent to an external server and leave the users vulnerable to additional attacks. By default, InfoPath users are only warned of a beaconing threat if the form originates from the Internet."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> Miscellaneous "Email Forms Beaconing UI" must be set to "Enabled (Always show UI)".

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\InfoPath\\security

Criteria: If the value EmailFormsBeaconingUI is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> Miscellaneous "Email Forms Beaconing UI" to "Enabled (Always show UI)".'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2013'
  tag check_id: 'C-47629r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17611'
  tag rid: 'SV-53384r1_rule'
  tag stig_id: 'DTOO176'
  tag gtitle: 'DTOO176 - Email forms beaconing UI'
  tag fix_id: 'F-46308r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
