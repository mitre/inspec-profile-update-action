control 'SV-254857' do
  title 'The Tanium Operating System (TanOS) must audit and notify system administrators and ISSOs when accounts are modified.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to modify an existing account. Notification of account modification is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail, which documents the modification of operating system user accounts and notifies the system administrator and ISSO of changes. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', '1. Access the TanOS interactively.

2. Press "A" for "Appliance Configuration Menu," and then press "Enter".

3. Press "4" for "Syslog Configuration," and then press "Enter".

4. Press "1" for "Check current status," and then press "Enter".

If the syslog status page states, "No existing TanOS syslog forwarding configuration found", this is a finding.

If the syslog status page states, "Syslog forwarding configuration", and the SIEM administrator verifies SIEM is receiving the events correctly and generating notifications for account modification events, this is not a finding.'
  desc 'fix', '1. Access the TanOS interactively.

2. Press "A" for "Appliance Configuration Menu," and then press "Enter".

3. Press "4" for "Syslog Configuration," and then press "Enter".

4. Press "5" for "Configure syslog forwarding," and then press "Enter".

5. Enter the destination host (IP address or hostname) provided by the SIEM administrator, and then press "Enter".

6. Enter the destination port number, and then press "Enter".

7. If TLS is required for this syslog destination, enter "Yes", otherwise enter "No", and then press "Enter".

8. Enter the destination protocol, "udp" or "tcp", and then press "Enter".

9. Work with the SIEM administrator to validate events are being received, and to configure notifications for account modification events.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58470r870380_chk'
  tag severity: 'medium'
  tag gid: 'V-254857'
  tag rid: 'SV-254857r870380_rule'
  tag stig_id: 'TANS-OS-000715'
  tag gtitle: 'SRG-OS-000275'
  tag fix_id: 'F-58414r866111_fix'
  tag 'documentable'
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
