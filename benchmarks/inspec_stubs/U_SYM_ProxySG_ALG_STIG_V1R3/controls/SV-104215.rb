control 'SV-104215' do
  title 'Symantec ProxySG must provide an alert to, at a minimum, the SCA and ISSO of all audit failure events where the detection and/or prevention function is unable to write events to either local storage or the centralized server.'
  desc 'Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify that the ProxySG is configured to send real-time alerts via SMTP and SNMP.

1. Log on to the Web Management Console.
2. Browse to Maintenance >> SNMP.
3. Verify that SNMP is enabled and configured.
4. Browse to "Event Logging".
5. Click "Mail" and verify that "Send Event Logs" is enabled and recipients are specified in the "Names" list and an SMTP server is specified.

If Symantec ProxySG does not provide an alert to, at a minimum, the SCA and ISSO of all audit failure events where the detection and/or prevention function is unable to write events to either local storage or the centralized server, this is a finding.'
  desc 'fix', 'Configure the ProxySG to send real-time alerts via SMTP and SNMP.

1. Log on to the Web Management Console.
2. Browse to Maintenance >> SNMP.
3. Check the "Enable SNMPv3" box. 
4. Click the SNMPv3 Users and SNMPv3 Traps tabs and configure per organizational specifications.
5. Browse to "Event Logging".
6. Click "Mail" and check the "Send Event Logs" box. 
7. Click "New" and add all desired recipients to the "Names" list.
8. Enter the correct SMTP server and port into the proper fields. 
9. Click "Apply".

For more information, see the ProxySG Administration Guide, Chapter 75: Monitoring the Appliance.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93447r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94261'
  tag rid: 'SV-104215r1_rule'
  tag stig_id: 'SYMP-AG-000230'
  tag gtitle: 'SRG-NET-000335-ALG-000053'
  tag fix_id: 'F-100377r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
