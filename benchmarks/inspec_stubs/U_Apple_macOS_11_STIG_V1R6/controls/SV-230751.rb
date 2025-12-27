control 'SV-230751' do
  title 'The macOS system must disable the SSHD service.'
  desc 'Without confidentiality and integrity protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., Remote Desktop Protocol [RDP]), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

Privileged access contains control and configuration information and is particularly sensitive, so additional protections are necessary. This is maintained by using cryptographic mechanisms, such as a hash function or digital signature, to protect integrity. 

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network.     

Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

The implementation of OpenSSH that is included with macOS does not utilize a FIPS 140-2 validated cryptographic module.

'
  desc 'check', 'Verify the "SSHD" service is disabled by using the following command:

/bin/launchctl print-disabled system | grep sshd

If the results do not show "com.openssh.sshd => true", this is a finding.'
  desc 'fix', 'Disable the "SSHD" service by using the following command:

usr/bin/sudo /bin/launchctl disable system/com.openssh.sshd

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33696r607140_chk'
  tag severity: 'medium'
  tag gid: 'V-230751'
  tag rid: 'SV-230751r599842_rule'
  tag stig_id: 'APPL-11-000011'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-33669r607141_fix'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000033-GPOS-00014', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-001453', 'CCI-001941', 'CCI-001942', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-002890', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'AC-17 (2)', 'IA-2 (8)', 'IA-2 (9)', 'SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)', 'MA-4 (6)', 'MA-4 (6)']
end
