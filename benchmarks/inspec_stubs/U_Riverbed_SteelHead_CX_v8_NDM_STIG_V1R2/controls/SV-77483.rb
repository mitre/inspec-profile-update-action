control 'SV-77483' do
  title 'Riverbed Optimization System (RiOS) must generate an alert that can be sent to security personnel when threats identified by authoritative sources (e.g., CTOs) and IAW with CJCSM 6510.01B occur.'
  desc 'By immediately displaying an alarm message, potential security violations can be identified more quickly even when administrators are not logged into the network device. An example of a mechanism to facilitate this would be through the utilization of SNMP traps.'
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

Navigate to the top of the web page and click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63745r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62993'
  tag rid: 'SV-77483r1_rule'
  tag stig_id: 'RICX-DM-000144'
  tag gtitle: 'SRG-APP-000516-NDM-000333'
  tag fix_id: 'F-68911r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001274']
  tag nist: ['CM-6 b', 'SI-4 (12)']
end
