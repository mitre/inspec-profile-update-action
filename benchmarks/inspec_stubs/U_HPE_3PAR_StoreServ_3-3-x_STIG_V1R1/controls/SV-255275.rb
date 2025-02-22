control 'SV-255275' do
  title 'The HPE 3PAR OS must be configured to send SNMP alerts to alert in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

The HPE 3PAR OS will send an SNMP trap event on any failure of audit components (failure to write a record, failure to send to remote syslog server, etc.). All of these conditions are automatically recovered Q20 in the short term. Configuration of the SNMP consumer is required to facilitate collection of these events.'
  desc 'check', 'Verify an SNMPv3 user account is configured:
cli%  showsnmpuser

Username                        | AuthProtocol    | PrivProtocol
3parsnmpuser                | HMAC SHA 96   |   CFB128 AES 128

If the output is not displayed in the above format, this is a finding.

Identify the SNMP trap recipient and report SNMP configuration:

cli%  showsnmpmgr

  HostIP                                            | Port  | SNMPVersion  | User
 <snmp trap recipient IP>        | 162    | 3                            | 3parsnmpuser

If the SNMP trap recipient IP address is incorrect, this is a finding.

If the SNMP port is not "162", this is a finding.

If the SNMP version is not "3", this is a finding.

If the SNMP user ID is incorrect, this is a finding.

Generate a test trap:
cli%  checksnmp

Trap sent to the following managers:
< IP address of trap recipient>

If the response does not indicate a trap was successfully sent, this is a finding.'
  desc 'fix', 'To configure SNMPv3 alert notifications, use this sequence of operations.

Create and enable an SNMPv3 user, and create associated keys for authentication and privacy:
cli% createuser 3parsnmpuser all browse
Enter the password and confirm

cli%  createsnmpuser 3parsnmpuser
at the prompt, enter the password
at the next prompt, re-enter the password.

Add the IP address of the SNMPv3 trap recipient, where permissions of the account are used:
cli%  addsnmpmgr -version 3 -snmpuser 3parsnmpuser  <ip address>'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58948r870142_chk'
  tag severity: 'medium'
  tag gid: 'V-255275'
  tag rid: 'SV-255275r870144_rule'
  tag stig_id: 'HP3P-33-001300'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-58892r870143_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
