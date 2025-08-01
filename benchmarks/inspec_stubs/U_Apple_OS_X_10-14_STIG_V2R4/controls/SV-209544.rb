control 'SV-209544' do
  title 'The macOS system must use replay-resistant authentication mechanisms and implement cryptographic mechanisms to protect the integrity of and verify remote disconnection at the termination of nonlocal maintenance and diagnostic communications, when used for nonlocal maintenance sessions.'
  desc 'Privileged access contains control and configuration information and is particularly sensitive, so additional protections are necessary. This is maintained by using cryptographic mechanisms, such as a hash function or digital signature, to protect integrity. 

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

The operating system can meet this requirement through leveraging a cryptographic module. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch). 

'
  desc 'check', 'To verify that the installed version of SSH is correct, run the following command:

ssh -V

If the string that is returned does not include "OpenSSH_7.9p1" or greater, this is a finding.

To check if the "SSHD" service is enabled, use the following commands:

/usr/bin/sudo launchctl print-disabled system | grep sshd

If the results do not show "com.openssh.sshd => false", this is a finding.

To check that "SSHD" is currently running, use the following command:

/usr/bin/sudo launchctl print system/com.openssh.sshd

If the result is the following, "Could not find service "com.openssh.sshd" in domain for system", this is a finding.'
  desc 'fix', 'To update SSHD to the minimum required version, run Software Update to update to the latest version of macOS.

To enable the SSHD service, run the following command:

/usr/bin/sudo /bin/launchctl enable system/com.openssh.sshd

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9795r466312_chk'
  tag severity: 'medium'
  tag gid: 'V-209544'
  tag rid: 'SV-209544r610285_rule'
  tag stig_id: 'AOSX-14-000040'
  tag gtitle: 'SRG-OS-000393-GPOS-00173'
  tag fix_id: 'F-9795r466313_fix'
  tag satisfies: ['SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058']
  tag 'documentable'
  tag legacy: ['SV-104715', 'V-95405']
  tag cci: ['CCI-002890', 'CCI-003123', 'CCI-001941', 'CCI-001942']
  tag nist: ['MA-4 (6)', 'MA-4 (6)', 'IA-2 (8)', 'IA-2 (9)']
end
