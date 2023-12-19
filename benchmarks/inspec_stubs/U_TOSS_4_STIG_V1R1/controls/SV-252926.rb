control 'SV-252926' do
  title 'The TOSS SSH daemon must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-2 validated cryptographic hash algorithms.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

TOSS incorporates system-wide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/openssh.config file.

By specifying a hash algorithm list with the order of hashes being in a "strongest to weakest" orientation, the system will automatically attempt to use the strongest hash for securing SSH connections.'
  desc 'check', %q(Verify the SSH daemon is configured to use only MACs employing FIPS 140-2-approved algorithms:

Check that the MACs in the back-end configurations are FIPS 140-2-approved algorithms with the following command:

$ sudo grep -i macs /etc/crypto-policies/back-ends/openssh.config /etc/crypto-policies/back-ends/opensshserver.config

/etc/crypto-policies/back-ends/openssh.config:MACs hmac-sha2-512,hmac-sha2-256
/etc/crypto-policies/back-ends/opensshserver.config:-oMACs=hmac-sha2-512,hmac-sha2-256'
/etc/crypto-policies/back-ends/opensshserver.config:-oMACs=hmac-sha2-512,hmac-sha2-256'

If the MAC entries in the "openssh.config" and "opensshserver.config" files have any hashes other than "hmac-sha2-512" and "hmac-sha2-256", the order differs from the example above, if they are missing, or commented out, this is a finding.)
  desc 'fix', %q(Configure the TOSS SSH daemon to use only MACs employing FIPS 140-2-approved algorithms.

Update the "/etc/crypto-policies/back-ends/openssh.config" 
and "/etc/crypto-policies/back-ends/opensshserver.config" files to include these MACs employing FIPS 140-2-approved algorithms:

/etc/crypto-policies/back-ends/openssh.config:MACs hmac-sha2-512,hmac-sha2-256
/etc/crypto-policies/back-ends/opensshserver.config:-oMACs=hmac-sha2-512,hmac-sha2-256'
/etc/crypto-policies/back-ends/opensshserver.config:-oMACs=hmac-sha2-512,hmac-sha2-256'

A reboot is required for the changes to take effect.)
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56379r824100_chk'
  tag severity: 'medium'
  tag gid: 'V-252926'
  tag rid: 'SV-252926r824102_rule'
  tag stig_id: 'TOSS-04-010160'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-56329r824101_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
