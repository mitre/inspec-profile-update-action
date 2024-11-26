control 'SV-228559' do
  title 'Document Information panel Beaconing must show UI.'
  desc 'This policy setting controls whether users see a security warning when they open custom Document Information Panels that contain a web beaconing threat.  Web beacons can be used to contact an external server when users open forms. Information could be gathered by the form, or information entered by users could be sent to an external server, exposing the internal users and systems to additional attacks.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Document Information Panel "Document Information Panel Beaconing UI" is set to "Enabled (Always show UI)".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\documentinformationpanel

If the value 'Beaconing' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Document Information Panel "Document Information Panel Beaconing UI" to "Enabled (Always show UI)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30792r498955_chk'
  tag severity: 'medium'
  tag gid: 'V-228559'
  tag rid: 'SV-228559r508020_rule'
  tag stig_id: 'DTOO207'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-30777r498956_fix'
  tag 'documentable'
  tag legacy: ['SV-52754', 'V-17605']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
