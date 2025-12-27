control 'SV-254862' do
  title 'The Tanium operating system (TanOS) must offload audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. 

Offloading is a common process in information systems with limited audit storage capacity.

'
  desc 'check', '1. Access the TanOS interactively.

2. Press "A" for "Appliance Configuration Menu," and then press "Enter".

3. Press "4" for "Syslog Configuration," and then press "Enter".

4. Press "1" for "Check current status," and then press "Enter".

If the syslog status page states "No existing TanOS syslog forwarding configuration found" this is a finding.

If the syslog status page states "Syslog forwarding configuration" and the SIEM administrator verifies that the destination SIEM is receiving the events correctly, this is not a finding.'
  desc 'fix', '1. Access the TanOS interactively.

2. Press "A" for "Appliance Configuration Menu," and then press "Enter".

3. Press "4" for "Syslog Configuration," and then press "Enter".

4. Press "5" for "Configure syslog forwarding," and then press "Enter".

5. Enter the destination host (IP address or hostname) provided by the SIEM administrator, and then press "Enter".

6. Enter the destination port number and press "Enter".

7. If TLS is required for this syslog destination, enter "Yes", otherwise enter "No", and then press "Enter".

8. Enter the destination protocol, "udp" or "tcp", and then press "Enter".

9. Work with the SIEM administrator to validate events are being received.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58475r866125_chk'
  tag severity: 'medium'
  tag gid: 'V-254862'
  tag rid: 'SV-254862r866127_rule'
  tag stig_id: 'TANS-OS-001030'
  tag gtitle: 'SRG-OS-000342'
  tag fix_id: 'F-58419r866126_fix'
  tag satisfies: ['SRG-OS-000342', 'SRG-OS-000479', 'SRG-OS-000215', 'SRG-OS-000062']
  tag 'documentable'
  tag cci: ['CCI-000169', 'CCI-001348', 'CCI-001851']
  tag nist: ['AU-12 a', 'AU-9 (2)', 'AU-4 (1)']
end
