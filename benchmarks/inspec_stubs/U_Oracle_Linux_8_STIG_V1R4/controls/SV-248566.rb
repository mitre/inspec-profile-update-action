control 'SV-248566' do
  title 'The OL 8 operating system must implement DoD-approved TLS encryption in the GnuTLS package.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection. 
 
Transport Layer Security (TLS) encryption is a required security setting as a number of known vulnerabilities have been reported against Secure Sockets Layer (SSL) and earlier versions of TLS. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party. SQL Server must use a minimum of FIPS 140-2 approved TLS version 1.2, and all non-FIPS-approved SSL and TLS versions must be disabled. NIST SP 800-52 specifies the preferred configurations for government systems. 
 
Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography, enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash. 
 
The GnuTLS library offers an API to access secure communications protocols. SSLv2 is not available in the GnuTLS library. The OL 8 system-wide crypto policy defines employed algorithms in the "/etc/crypto-policies/back-ends/gnutls.config" file.'
  desc 'check', 'Verify the GnuTLS library is configured to only allow DoD-approved SSL/TLS versions: 
 
$ sudo grep -io +vers.* /etc/crypto-policies/back-ends/gnutls.config 
 
+VERS-ALL:-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0:+COMP-NULL:%PROFILE_MEDIUM 
 
If the "gnutls.config" does not list "-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0" to disable unapproved SSL/TLS versions, this is a finding.'
  desc 'fix', 'Configure the OL 8 GnuTLS library to use only DoD-approved encryption by adding the following line to "/etc/crypto-policies/back-ends/gnutls.config": 
 
+VERS-ALL:-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0 
 
A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52000r818618_chk'
  tag severity: 'medium'
  tag gid: 'V-248566'
  tag rid: 'SV-248566r818619_rule'
  tag stig_id: 'OL08-00-010295'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-51954r779263_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
