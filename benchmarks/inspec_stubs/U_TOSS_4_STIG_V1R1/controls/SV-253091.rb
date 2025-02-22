control 'SV-253091' do
  title 'TOSS must implement DoD-approved encryption in the OpenSSL package.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

TOSS incorporates system-wide crypto policies by default. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/openssl.config file.'
  desc 'check', 'Verify the OpenSSL library is configured to use only ciphers employing FIPS 140-2-approved algorithms:

Verify that system-wide crypto policies are in effect:

$ sudo grep -i opensslcnf.config /etc/pki/tls/openssl.cnf

.include /etc/crypto-policies/back-ends/opensslcnf.config

If the "opensslcnf.config" is not defined in the "/etc/pki/tls/openssl.cnf" file, this is a finding.

Verify which system-wide crypto policy is in use:

$ sudo update-crypto-policies --show

FIPS:OSPP

If the system-wide crypto policy is set to anything other than "FIPS" or "FIPS:OSPP", this is a finding.'
  desc 'fix', 'Configure the TOSS OpenSSL library to use only ciphers employing FIPS 140-2-approved algorithms with the following command:

$ sudo fips-mode-setup --enable

A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56544r824943_chk'
  tag severity: 'medium'
  tag gid: 'V-253091'
  tag rid: 'SV-253091r824945_rule'
  tag stig_id: 'TOSS-04-040440'
  tag gtitle: 'SRG-OS-000393-GPOS-00173'
  tag fix_id: 'F-56494r824944_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
