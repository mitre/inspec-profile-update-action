control 'SV-248562' do
  title 'The OL 8 SSH server must be configured to use only ciphers employing FIPS 140-2 validated cryptographic algorithms.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised. 
 
Operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 
 
FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.

The system will attempt to use the first hash presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest cipher available to secure the SSH connection.'
  desc 'check', %q(Verify the OL 8 SSH server is configured to use only ciphers employing FIPS 140-2 approved algorithms with the following command: 
  
$ sudo grep -i ciphers /etc/crypto-policies/back-ends/opensshserver.config 
 
CRYPTO_POLICY='-oCiphers=aes256-ctr,aes192-ctr,aes128-ctr' 
 
If the cipher entries in the "opensshserver.config" file have any ciphers other than "aes256-ctr,aes192-ctr,aes128-ctr", the order differs from the example above, or they are missing or commented out, this is a finding.)
  desc 'fix', %q(Configure the OL 8 SSH server to use only ciphers employing FIPS 140-2 approved algorithms: 

Update the "/etc/crypto-policies/back-ends/opensshserver.config" file to include these ciphers employing FIPS 140-2-approved algorithms: 
 
CRYPTO_POLICY='-oCiphers=aes256-ctr,aes192-ctr,aes128-ctr'
 
A reboot is required for the changes to take effect.)
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51996r779250_chk'
  tag severity: 'medium'
  tag gid: 'V-248562'
  tag rid: 'SV-248562r779252_rule'
  tag stig_id: 'OL08-00-010291'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-51950r779251_fix'
  tag 'documentable'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
