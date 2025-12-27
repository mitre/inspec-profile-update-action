control 'SV-225126' do
  title 'The macOS system must implement DoD-approved encryption to protect the confidentiality and integrity of remote access sessions, including transmitted data and data during preparation for transmission, and use replay-resistant authentication mechanisms and implement cryptographic mechanisms to protect the integrity of and verify remote disconnection at the termination of nonlocal maintenance and diagnostic communications.'
  desc 'Without confidentiality and integrity protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., Remote Desktop Protocol [RDP]), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

Privileged access contains control and configuration information and is particularly sensitive, so additional protections are necessary. This is maintained by using cryptographic mechanisms, such as a hash function or digital signature, to protect integrity. 

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

The operating system can meet this requirement through leveraging a cryptographic module. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).

SSHD should be enabled to facilitate secure remote access.

'
  desc 'check', 'To verify that the installed version of SSH is correct, run the following command:

ssh -V

If the string that is returned does not include "OpenSSH_7.9p1" or greater, this is a finding.

To check if the "SSHD" service is enabled, use the following commands:

/usr/bin/sudo launchctl print-disabled system | grep sshd

If the results do not "com.openssh.sshd => false", this is a finding:

To check that "SSHD" is currently running, use the following command:

/usr/bin/sudo launchctl print system/com.openssh.sshd

If the result is the following, this is a finding:

"Could not find service "com.openssh.sshd" in domain for system"'
  desc 'fix', 'To update SSHD to the minimum required version, run Software Update to update to the latest version of macOS.

To enable the SSHD service, run the following command:

/usr/bin/sudo /bin/launchctl enable system/com.openssh.sshd

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26825r467546_chk'
  tag severity: 'medium'
  tag gid: 'V-225126'
  tag rid: 'SV-225126r877394_rule'
  tag stig_id: 'AOSX-15-000011'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-26813r853307_fix'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000033-GPOS-00014', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag legacy: ['V-102667', 'SV-111629']
  tag cci: ['CCI-000068', 'CCI-001453', 'CCI-001941', 'CCI-001942', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-002890', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'AC-17 (2)', 'IA-2 (8)', 'IA-2 (9)', 'SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)', 'MA-4 (6)', 'MA-4 (6)']
end
