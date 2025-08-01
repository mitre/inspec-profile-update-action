control 'SV-252925' do
  title 'The TOSS operating system must implement DoD-approved TLS encryption in the GnuTLS package.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Transport Layer Security (TLS) encryption is a required security setting as a number of known vulnerabilities have been reported against Secure Sockets Layer (SSL) and earlier versions of TLS. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party. SQL Server must use a minimum of FIPS 140-2-approved TLS version 1.2, and all non-FIPS-approved SSL and TLS versions must be disabled. NIST SP 800-52 specifies the preferred configurations for government systems.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

The GnuTLS library offers an API to access secure communications protocols. SSLv2 is not available in the GnuTLS library. The TOSS system-wide crypto policy defines employed algorithms in the /etc/crypto-policies/back-ends/gnutls.config file.5'
  desc 'check', 'Verify the GnuTLS library is configured to only allow DoD-approved SSL/TLS Versions:

$ sudo grep -io +vers.* /etc/crypto-policies/back-ends/gnutls.config

+VERS-ALL:-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0:+COMP-NULL:%PROFILE_MEDIUM

If the "gnutls.config" does not list "-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0" to disable unapproved SSL/TLS versions, this is a finding.'
  desc 'fix', 'Configure the TOSS GnuTLS library to use only DoD-approved encryption by adding the following line to "/etc/crypto-policies/back-ends/gnutls.config":

+VERS-ALL:-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0

A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56378r824097_chk'
  tag severity: 'medium'
  tag gid: 'V-252925'
  tag rid: 'SV-252925r824099_rule'
  tag stig_id: 'TOSS-04-010150'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-56328r824098_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
