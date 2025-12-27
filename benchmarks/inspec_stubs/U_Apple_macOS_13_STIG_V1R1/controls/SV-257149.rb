control 'SV-257149' do
  title 'The macOS system must disable the SSHD service.'
  desc 'Without confidentiality and integrity protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., Remote Desktop Protocol [RDP]), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

Privileged access contains control and configuration information and is particularly sensitive, so additional protections are necessary. This is maintained by using cryptographic mechanisms, such as a hash function or digital signature, to protect integrity.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.

Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

The implementation of OpenSSH that is included with macOS does not use a FIPS 140-2 validated cryptographic module.

'
  desc 'check', 'Verify the macOS system is configured to disable the "SSHD" service with the following command:

/bin/launchctl print-disabled system | /usr/bin/grep com.openssh.sshd

"com.openssh.sshd" => disabled

If the results are not "com.openssh.sshd => disabled", this is a finding.'
  desc 'fix', 'Configure the macOS system to disable the "SSHD" service with the following command:

/usr/bin/sudo /bin/launchctl disable system/com.openssh.sshd

The system may need to be restarted for the update to take effect.'
  impact 0.7
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60834r905078_chk'
  tag severity: 'high'
  tag gid: 'V-257149'
  tag rid: 'SV-257149r905080_rule'
  tag stig_id: 'APPL-13-000011'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-60775r905079_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000379-GPOS-00164', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-001453', 'CCI-001941', 'CCI-001942', 'CCI-001967', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-002890', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'AC-17 (2)', 'IA-2 (8)', 'IA-2 (9)', 'IA-3 (1)', 'SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)', 'MA-4 (6)', 'MA-4 (6)']
end
