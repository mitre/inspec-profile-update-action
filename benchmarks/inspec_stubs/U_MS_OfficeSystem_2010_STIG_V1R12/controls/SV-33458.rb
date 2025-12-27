control 'SV-33458' do
  title 'Document Information panel Beaconing must show UI.'
  desc 'For controlling whether users see a security warning when they open custom Document Information Panels that contain a Web beaconing threat.  Web beacons can be used to contact an external server when users open forms. Information could be gathered by the form, or information entered by users could be sent to an external server and cause them to be vulnerable to additional attacks.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Document Information Panel “Document Information Panel Beaconing UI” must be set to “Enabled (Always show UI)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\documentinformationpanel

Criteria: If the value Beaconing is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Document Information Panel “Document Information Panel Beaconing UI” to “Enabled (Always show UI)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33941r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17605'
  tag rid: 'SV-33458r1_rule'
  tag stig_id: 'DTOO207 - Office System'
  tag gtitle: 'DTOO207 - Document Info Beaconing UI'
  tag fix_id: 'F-29630r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
