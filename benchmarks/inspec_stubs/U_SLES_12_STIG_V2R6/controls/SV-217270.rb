control 'SV-217270' do
  title 'The SUSE operating system must implement DoD-approved encryption to protect the confidentiality of SSH remote connections.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

The system will attempt to use the first cipher presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest cipher available to secure the SSH connection.

'
  desc 'check', %q(Verify that the SUSE operating system implements DoD-approved encryption to protect the confidentiality of SSH remote connections.

Check the SSH daemon configuration for allowed ciphers with the following command:

# sudo grep -i ciphers /etc/ssh/sshd_config | grep -v '^#'

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

If any ciphers other than "aes256-ctr", "aes192-ctr", or "aes128-ctr" are listed, the order differs from the example above, the "Ciphers" keyword is missing, or the returned line is commented out, this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration (/etc/ssh/sshd_config) and remove any ciphers not starting with "aes" and remove any ciphers ending with "cbc". If necessary, add a "Ciphers" line:

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

Restart the SSH daemon:

# sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18498r622418_chk'
  tag severity: 'medium'
  tag gid: 'V-217270'
  tag rid: 'SV-217270r744120_rule'
  tag stig_id: 'SLES-12-030170'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-18496r622419_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173']
  tag 'documentable'
  tag legacy: ['V-77455', 'SV-92151']
  tag cci: ['CCI-000803', 'CCI-000366', 'CCI-000068', 'CCI-002890']
  tag nist: ['IA-7', 'CM-6 b', 'AC-17 (2)', 'MA-4 (6)']
end
