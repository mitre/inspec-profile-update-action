control 'SV-77407' do
  title 'Riverbed Optimization System (RiOS) must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.'
  desc 'check', 'Verify that RiOS uses automated mechanisms to alert security personnel to threats identified by authoritative sources.

Navigate to the device Management Console
Navigate to Configure >> System Settings >> SNMP Basic

Verify that Host Servers are defined in the section "Trap Receivers"

If there are no Host Servers defined in "Trap Receivers", this is a finding.'
  desc 'fix', 'Configure RiOS to use automated mechanisms to alert security personnel to threats identified by authoritative sources.

Navigate to the device Management Console
Navigate to Configure >> System Settings >> SNMP Basic
Click "Add a New Trap Receiver"
Set "Receiver IP Address" to the address of the trap receiver
Set "Destination Port:" to the port that the Trap Receiver is listening on
Set "Receiver Type:" to "v3"
Set "Remote User:" to the user name on the Trap Receiver
Set "Authentication:" to <Supply a key based>
Set "Authentication Protocol:" to "SHA" 
SHA Key: <enter the SHA key>
Set "Security Level:" to "Auth/Priv"
Set "Privacy Protocol:" to "AES"
Set "Privacy:" to Select "same as Authentication Key"
Set "Enable Receiver"
Click "Add"

Navigate to the top of the web page and click "Save" to save these settings permanently.'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63669r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62917'
  tag rid: 'SV-77407r1_rule'
  tag stig_id: 'RICX-DM-000054'
  tag gtitle: 'SRG-APP-000108-NDM-000232'
  tag fix_id: 'F-68835r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
