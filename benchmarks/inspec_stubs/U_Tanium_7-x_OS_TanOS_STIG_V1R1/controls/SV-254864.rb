control 'SV-254864' do
  title 'The Tanium operating system (TanOS) must provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', '1. Access the TanOS interactively.

2. Press "A" for "Appliance Configuration Menu," and then press "Enter".

3. Press "4" for "Syslog Configuration," and then press "Enter".

4. Press "1" for "Check current status," and then press "Enter".

If the syslog status page states "No existing TanOS syslog forwarding configuration found" this is a finding.

If the syslog status page states "Syslog forwarding configuration" and the SIEM administrator verifies SIEM is receiving the events correctly and generating notifications for audit failure events, this is not a finding.'
  desc 'fix', '1. Access the TanOS interactively.

2. Press "A" for "Appliance Configuration Menu," and then press "Enter".

3. Press "4" for "Syslog Configuration," and then press "Enter".

4. Press "5" for "Configure syslog forwarding," and then press "Enter".

5. Enter the destination host (IP address or hostname) provided by the SIEM administrator, and then press "Enter".

6. Enter the destination port number and press "Enter".

7. If TLS is required for this syslog destination, enter "Yes", otherwise enter "No", and press "Enter".

8. Enter the destination protocol, "udp" or "tcp", and press "Enter".

9. Work with the SIEM administrator to validate events are being received, and to configure notifications for audit failure events.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58477r866131_chk'
  tag severity: 'medium'
  tag gid: 'V-254864'
  tag rid: 'SV-254864r866133_rule'
  tag stig_id: 'TANS-OS-001040'
  tag gtitle: 'SRG-OS-000344'
  tag fix_id: 'F-58421r866132_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
