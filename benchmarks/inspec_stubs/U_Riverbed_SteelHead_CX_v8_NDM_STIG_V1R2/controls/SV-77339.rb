control 'SV-77339' do
  title 'Riverbed Optimization System (RiOS) must generate alerts that can be forwarded to the administrators and ISSO when accounts are modified.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply modify an existing account. Notification of account modification is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the modification of device administrator accounts and notifies administrators and Information System Security Officers (ISSO). Such a process greatly reduces the risk that accounts will be surreptitiously modified and provides logging that can be used for forensic purposes.

The network device must generate the alert. Notification may be done by a management server.'
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
  tag check_id: 'C-63643r1_chk'
  tag severity: 'low'
  tag gid: 'V-62849'
  tag rid: 'SV-77339r1_rule'
  tag stig_id: 'RICX-DM-000012'
  tag gtitle: 'SRG-APP-000292-NDM-000276'
  tag fix_id: 'F-68767r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
