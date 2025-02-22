control 'SV-254854' do
  title 'The Tanium Operating System (TanOS) must notify the ISSO and ISSM of failed security verification tests.'
  desc 'If personnel are not notified of failed security verification tests, they will not be able to take corrective action and the unsecure condition(s) will remain. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include electronic alerts, messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', '1. Access the TanOS interactively.

2. Press "A" for "Appliance Configuration Menu," and then press "Enter".

3. Press "4" for "Syslog Configuration," and press then "Enter".

4. Press "1" for "Check current status," and then press "Enter".

If the syslog status page states, "No existing TanOS syslog forwarding configuration found", this is a finding.

If the syslog status page states, "Syslog forwarding configuration" and the SIEM administrator verifies SIEM is receiving the events correctly and generating notifications for failed security verification tests, this is not a finding.'
  desc 'fix', '1. Access the TanOS interactively.

2. Press "A" for "Appliance Configuration Menu," and then press "Enter".

3. Press "4" for "Syslog Configuration," and then press "Enter".

4. Press "5" for "Configure syslog forwarding," and then press "Enter".

5. Enter the destination host (IP address or hostname) provided by the SIEM administrator, and press "Enter".

6. Enter the destination port number, and then press "Enter".

7. If TLS is required for this syslog destination, enter "Yes", otherwise enter "No", and then press "Enter".

8. Enter the destination protocol, "udp" or "tcp", and then press "Enter".

9. Work with the SIEM administrator to validate events are being received, and to configure notifications for failure events.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58467r870378_chk'
  tag severity: 'medium'
  tag gid: 'V-254854'
  tag rid: 'SV-254854r870378_rule'
  tag stig_id: 'TANS-OS-000535'
  tag gtitle: 'SRG-OS-000200'
  tag fix_id: 'F-58411r866102_fix'
  tag 'documentable'
  tag cci: ['CCI-001294']
  tag nist: ['SI-6 c']
end
