control 'SV-248561' do
  title 'The OL 8 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-2 validated cryptographic hash algorithms.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection. 
 
Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
 
Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography, enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash. 
 
OL 8 incorporates system-wide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the "/etc/sysconfig/sshd" file. The employed algorithms can be viewed in the "/etc/crypto-policies/back-ends/opensshserver.config" file.

The system will attempt to use the first hash presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest hash available to secure the SSH connection.'
  desc 'check', 'Verify the SSH server is configured to use only MACs employing FIPS 140-2-approved algorithms with the following command:

$ sudo grep -i macs /etc/crypto-policies/back-ends/opensshserver.config

-oMACS=hmac-sha2-512,hmac-sha2-256

If the MAC entries in the "opensshserver.config" file have any hashes other than "hmac-sha2-512" and "hmac-sha2-256", the order differs from the example above, if they are missing, or commented out, this is a finding.'
  desc 'fix', 'Configure the OL 8 SSH server to use only MACs employing FIPS 140-2 approved algorithms:

Update the "/etc/crypto-policies/back-ends/opensshserver.config" file to include these MACs employing FIPS 140-2 approved algorithms: 
 
-oMACS=hmac-sha2-512,hmac-sha2-256 
 
A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51995r779247_chk'
  tag severity: 'medium'
  tag gid: 'V-248561'
  tag rid: 'SV-248561r877395_rule'
  tag stig_id: 'OL08-00-010290'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-51949r779248_fix'
  tag 'documentable'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
