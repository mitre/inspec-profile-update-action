control 'SV-77341' do
  title 'Riverbed Optimization System (RiOS) must generate alerts that can be forwarded to the administrators and ISSO when accounts are disabled.'
  desc 'When application accounts are disabled, administrator accessibility is affected. Accounts are utilized for identifying individual device administrators or for identifying the device processes themselves. 

In order to detect and respond to events that affect administrator accessibility and device processing, devices must audit account disabling actions and, as required, notify the appropriate individuals so they can investigate the event. Such a capability greatly reduces the risk that device accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.'
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
Set "Receiver Type:" to v3
Set "Remote User:" to the user name on the Trap Receiver
Set "Authentication:" to <Supply a key based>
Set "Authentication Protocol:" to SHA 
SHA Key: <enter the SHA key>
Set "Security Level:" to Auth/Priv
Set "Privacy Protocol:" to "AES"
Set "Privacy:" to Select "same as Authentication Key"
Set "Enable Receiver"
Click "Add"

Navigate to the top of the web page and click "Save" to save these settings permanently.'
  impact 0.3
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63645r1_chk'
  tag severity: 'low'
  tag gid: 'V-62851'
  tag rid: 'SV-77341r1_rule'
  tag stig_id: 'RICX-DM-000013'
  tag gtitle: 'SRG-APP-000293-NDM-000277'
  tag fix_id: 'F-68769r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
