control 'SV-252919' do
  title 'The TOSS operating system must implement DoD-approved encryption in the OpenSSL package.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

TOSS incorporates system-wide crypto policies by default. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/openssl.config file.

'
  desc 'check', 'Verify the OpenSSL library is configured to use only DoD-approved TLS encryption:

$ sudo grep -i MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config

TLS.MinProtocol = TLSv1.2
DTLS.MinProtocol = DTLSv1.2

If the "TLS.MinProtocol" is set to anything older than "TLSv1.2" or the "DTLS.MinProtocol" is set to anything older than DTLSv1.2, this is a finding.'
  desc 'fix', 'Configure the TOSS OpenSSL library to use only DoD-approved TLS encryption by editing the following lines in the "/etc/crypto-policies/back-ends/opensslcnf.config" file:

MinProtocol = TLSv1.2
DTLS.MinProtocol = DTLSv1.2

A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56372r824079_chk'
  tag severity: 'medium'
  tag gid: 'V-252919'
  tag rid: 'SV-252919r824081_rule'
  tag stig_id: 'TOSS-04-010080'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-56322r824080_fix'
  tag satisfies: ['SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093']
  tag 'documentable'
  tag cci: ['CCI-000877', 'CCI-001453']
  tag nist: ['MA-4 c', 'AC-17 (2)']
end
