control 'SV-219312' do
  title 'The Ubuntu operating system must configure the SSH daemon to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms to protect the integrity of nonlocal maintenance and diagnostic communications.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

'
  desc 'check', 'Verify the Ubuntu operating system configures the SSH daemon to only use Message Authentication Codes (MACs) that employ FIPS 140-2 approved ciphers.

Check that the SSH daemon is configured to only use MACs that employ FIPS 140-2 approved ciphers with the following command:

# sudo grep -i macs /etc/ssh/sshd_config

MACs hmac-sha2-512,hmac-sha2-256

If any ciphers other than "hmac-sha2-512" or "hmac-sha2-256" are listed, the order differs from the example above, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to allow the SSH daemon to only use Message Authentication Codes (MACs) that employ FIPS 140-2 approved ciphers.

Add the following line (or modify the line to have the required value) to the "/etc/ssh/sshd_config" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

MACs hmac-sha2-512,hmac-sha2-256

In order for the changes to take effect, reload the SSH daemon.

# sudo systemctl reload sshd.service'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21037r621656_chk'
  tag severity: 'medium'
  tag gid: 'V-219312'
  tag rid: 'SV-219312r610963_rule'
  tag stig_id: 'UBTU-18-010417'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-21036r621657_fix'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag legacy: ['V-100847', 'SV-109951']
  tag cci: ['CCI-002890', 'CCI-003123', 'CCI-001453']
  tag nist: ['MA-4 (6)', 'MA-4 (6)', 'AC-17 (2)']
end
