control 'SV-234816' do
  title 'The SUSE operating system must implement DoD-approved encryption to protect the confidentiality of SSH remote connections.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

By specifying a cipher list with the order of ciphers being in a "strongest to weakest" orientation, the system will automatically attempt to use the strongest cipher for securing SSH connections.

'
  desc 'check', %q(Verify that the SUSE operating system implements DoD-approved encryption to protect the confidentiality of SSH remote connections.

Check the SSH daemon configuration for allowed ciphers with the following command:

> sudo grep -i ciphers /etc/ssh/sshd_config | grep -v '^#'

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

If any ciphers other than "aes256-ctr", "aes192-ctr", or "aes128-ctr" are listed, the order differs from the example above, or the "Ciphers" keyword is missing,  this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration (/etc/ssh/sshd_config) and remove any ciphers not starting with "aes" and remove any ciphers ending with "cbc". If necessary, add a "Ciphers" line:

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

Restart the SSH daemon:

> sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38004r618717_chk'
  tag severity: 'medium'
  tag gid: 'V-234816'
  tag rid: 'SV-234816r622137_rule'
  tag stig_id: 'SLES-15-010160'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-37967r618718_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173']
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
