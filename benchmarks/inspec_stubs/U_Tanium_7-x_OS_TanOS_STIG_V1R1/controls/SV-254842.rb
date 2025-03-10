control 'SV-254842' do
  title 'The Tanium operating system (TanOS) must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', '1. Access the TanOS interactively.

2. Press "A" for "Appliance Configuration Menu," and then press "Enter".

3. Press 4 for "Syslog Configuration," and then press "Enter".

4. Press "1" for "Check current status," and then press Enter.

If the syslog status page states, "No existing TanOS syslog forwarding configuration found", this is a finding.

If the syslog status page states, "Syslog forwarding configuration" and the SIEM administrator verifies SIEM is receiving the events correctly and generating notifications for audit processing failure events, this is not a finding.'
  desc 'fix', '1. Access the TanOS interactively.

2. Press A for "Appliance Configuration Menu," and then press "Enter".

3. Press "4" for "Syslog Configuration," and then press "Enter".

4. Press 5 for "Configure syslog forwarding," and then press "Enter".

5. Enter the destination host (IP address or hostname) provided by the SIEM administrator, and then press "Enter".

6. Enter the destination port number and press "Enter".

7. If TLS is required for this syslog destination, enter "Yes", otherwise enter "No", and then press "Enter".

8. Enter the destination protocol, "udp" or "tcp", and then press "Enter".

9. Work with the SIEM administrator to validate events are being received, and to configure notifications for audit processing failure events.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58455r870377_chk'
  tag severity: 'medium'
  tag gid: 'V-254842'
  tag rid: 'SV-254842r870377_rule'
  tag stig_id: 'TANS-OS-000165'
  tag gtitle: 'SRG-OS-000046'
  tag fix_id: 'F-58399r866066_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
