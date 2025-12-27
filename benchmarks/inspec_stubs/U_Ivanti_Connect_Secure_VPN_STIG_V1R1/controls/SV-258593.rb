control 'SV-258593' do
  title 'The ICS must be configured to forward all log failure events where the detection and/or prevention function is unable to write events to local log record or send an SNMP trap that can be forwarded to the SCA and ISSO.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Automated alerts can be conveyed in a variety of ways, including, for example, telephonically, via electronic mail, via text message, or via websites. Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded.

The VPN daemon facility and log facility are messages in the log, which capture actions performed or errors encountered by system processes.'
  desc 'check', 'If SNMP is used, verify the configuration is compliant. If SNMP is not used, this is not a finding.

In the ICS Web UI, navigate to System >> Log/Monitoring >> SNMP.
1. Under "Agent Properties", verify "SNMP Traps" is checked.
2. Under "SNMP Version data", verify "v3" is selected.
3. Under "User 1", verify a user configuration in AuthPriv is using at least SHA and CFB-AES-128.
4. Verify "Optional Traps Critical and Major Log Events" are checked.
5. Verify the SNMP server IPv4/IPv6 address is configured under "SNMP Trap Servers".

If SNMP is incorrectly configured, this is a finding.'
  desc 'fix', 'Event logs are also updated to local logs by default in addition to the central syslog server. However, if the site uses SNMP, the following must be configured since SNMP is disabled by default.

In the ICS Web UI, navigate to System >> Log/Monitoring >> SNMP.
1. Under "SNMP Version data", select "v3".
2. Under "Agent Properties", check "SNMP Traps".
3. Under "Agent Properties", configure a System Name, Location, and Contact.
4. Under "User 1", type in a valid username. Select "AuthPriv".
- The auth protocol must be set to at least SHA. Type the Auth Password.
- The priv protocol must be set to at least CFB-AES-128. Type in the priv password.
5. Under "Trap Thresholds", ensure "Check Frequency" is 180 seconds, "Log Capacity" is 75%, "Users" is 100%, "Physical Memory" is 0%, "Swap Memory" is 0%, "Disk" is 75%, "CPU" is 0%, and "Meeting Users" is 100%.
6. Under "Optional Traps", check the boxes for "Critical and Major Log Events".
7. Under "SNMP Trap Servers", configure an IPv4/IPv6 address for the valid trap server/receiver, type in the port (default is 162), and select the user to use (use the user from step #4 above).'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62333r930465_chk'
  tag severity: 'medium'
  tag gid: 'V-258593'
  tag rid: 'SV-258593r930467_rule'
  tag stig_id: 'IVCS-VN-000310'
  tag gtitle: 'SRG-NET-000335-VPN-001270'
  tag fix_id: 'F-62242r930466_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
