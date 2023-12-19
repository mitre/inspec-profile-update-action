control 'SV-217271' do
  title 'The SUSE operating system SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

By specifying a hash algorithm list with the order of hashes being in a “strongest to weakest” orientation, the system will automatically attempt to use the strongest hash for securing SSH connections.

'
  desc 'check', 'Verify the SUSE operating system SSH daemon is configured to only use MACs that employ FIPS 140-2 approved hashes.

Check that the SSH daemon is configured to only use MACs that employ FIPS 140-2 approved hashes with the following command:

# sudo grep -i macs /etc/ssh/sshd_config
MACs hmac-sha2-512,hmac-sha2-256

If any hashes other than "hmac-sha2-512" or "hmac-sha2-256" are listed, the order differs from the example above, they are missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system SSH daemon to only use MACs that employ FIPS 140-2 approved hashes.

Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the "MACs" keyword and set its value to "hmac-sha2-512" and/or "hmac-sha2-256" (The file might be named differently or be in a different location):

MACs hmac-sha2-512,hmac-sha2-256'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18499r622421_chk'
  tag severity: 'medium'
  tag gid: 'V-217271'
  tag rid: 'SV-217271r603959_rule'
  tag stig_id: 'SLES-12-030180'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-18497r622422_fix'
  tag satisfies: ['SRG-OS-000125-GPOS-00065', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag legacy: ['SV-92153', 'V-77457']
  tag cci: ['CCI-001453', 'CCI-000877', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'MA-4 c', 'MA-4 (6)']
end
