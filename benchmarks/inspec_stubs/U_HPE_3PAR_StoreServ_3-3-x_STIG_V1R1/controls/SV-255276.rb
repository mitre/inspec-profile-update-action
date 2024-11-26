control 'SV-255276' do
  title 'The HPE 3PAR OS must provide an immediate real-time alert to the System Administrator (SA) and Information System Security Officer (ISSO), at a minimum, of all audit failure events requiring real-time alerts.'
  desc "It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).

In HPE 3PAR OS all event logging responsibility is shared among the clustered nodes. If one node should panic, a surviving node will issue an SNMP trap, and take over event log management, recording the failure messages from the panic'ing node. If the panic'ing node was also the network owner (responsible for communications with outside entities such as the SIEM system), another node will take over the network ownership. Any messages not yet sent will be sent to the SIEM system at this time. When the panic'd node reboots, it will simply rejoin the cluster as a participant."
  desc 'check', 'Verify that an SNMPV3 user account is configured:

cli% showsnmpuser

Username                        | AuthProtocol    | PrivProtocol
<someusername>   | HMAC SHA 96   |   CFB128 AES 128

If the output is not in the above format, this is a finding.

Verify the SNMP trap recipient and SNMP configuration:

cli% showsnmpmgr

If the HostIP identified is not correct, this is a finding.

If the port is not 162, this is a finding.

If the version is not 3, this is a finding.

If the username does not match the user from above, this is a finding.

Send a test trap and verify it is received:

cli% checksnmp

If the response does not indicate a trap was successfully sent, this is a finding.'
  desc 'fix', 'Configure SNMPV3 notifications.

Create an SNMPV3 user, and create associated keys for authentication and privacy.

cli% createsnmpuser <someusername>
where "<someusername>" is the desired username, and then enter a password at the prompts.

Add the SNMP trap recipient and the user just created.

cli%  addsnmpmgr -version 3 -snmpuser <someusername> <ipaddress>
where "<someusername>" is the user created above, and "<ipaddress>" is the address of the SNMPV3 trap recipient.

Generate a test trap:
cli% checksnmp

Verify that a trap was received by the manager specified.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58949r870145_chk'
  tag severity: 'medium'
  tag gid: 'V-255276'
  tag rid: 'SV-255276r870147_rule'
  tag stig_id: 'HP3P-33-001301'
  tag gtitle: 'SRG-OS-000344-GPOS-00135'
  tag fix_id: 'F-58893r870146_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
