control 'SV-55867' do
  title 'DBMS cryptography must be NIST FIPS 140-2 validated.'
  desc 'Use of cryptography to provide confidentiality and non-repudiation is not effective unless strong methods are employed with its use. Many earlier encryption methods and modules have been broken and/or overtaken by increasing computing power. The NIST FIPS 140-2 cryptographic standards provide proven methods and strengths to employ cryptography effectively.'
  desc 'check', "Verify organizational requirements for encryption based on the system's data classification.  If DBMS encryption is not required, this check is not a finding.

If DBMS encryption is required and cryptography is either not being used or is not NIST FIPS 140-2 certified, this is a Finding.

Maintain a copy of the FIPS 140-2 Validation Certificate for the cryptographic modules in use as proof of certification.

Detailed information on the NIST Cryptographic Module Validation Program (CMVP) is available at the following website:

http://csrc.nist.gov/groups/STM/cmvp/index.html

--

Review the DBMS documentation to determine where cryptography may be used and/or configured.

Review network communication encryption options, data object encryption (both tables and application code objects), and encryption key management.

For UNIX systems:
  $ORACLE_HOME/OPatch/opatch lsinventory –detail | grep “Oracle Advanced Security”

For Windows Systems:
  %ORACLE_HOME%/OPatch/opatch lsinventory –detail | find “Oracle Advanced Security”

If DBMS data/network encryption is required and Oracle Advanced Security is not installed, this is a Finding.

View the SQLNET.ORA file.

If SQLNET.SSLFIPS_140 = TRUE is not set, this is a Finding.

If SSL_CIPHER_SUITES is not defined, this is a Finding.

If any cipher suites listed in SSL_CIPHER_SUITES value list is not included in the cipher suite list included below (and in this order), this is a Finding.

FIPS 140-2 validated cipher suites for the Oracle SSL Libraries in the order of strongest to weakest:

SSL_RSA_WITH_AES_256_CBC_SHA
SSL_RSA_WITH_AES_128_CBC_SHA 
SSL_RSA_WITH_3DES_EDE_CBC_SHA 
SSL_RSA_WITH_RC4_128_SHA 
SSL_RSA_WITH_RC4_128_MD5 
SSL_RSA_WITH_DES_CBC_SHA 
SSL_DH_anon_WITH_3DES_EDE_CBC_SHA 
SSL_DH_anon_WITH_RC4_128_MD5 
SSL_DH_anon_WITH_DES_CBC_SHA

Detailed information on the FIPS 140-2 standard is available at the following website:

http://csrc.nist.gov/groups/SMA/index.html"
  desc 'fix', "Obtain and utilize native or third-party NIST FIPS 140-2 validated cryptography solution for the DBMS.

Installation of Oracle Advanced Security product (which may require additional Oracle licensing consideration) is required to use native Oracle encryption.

Please see the Oracle Advanced Security Administrator's Guide for configuration and use of encryption in the database. The Oracle Advanced Security Administrator's Guide provides references to the encryption features provided by Oracle Advanced Security.

Instructions for the configuration of FIPS 140-2 compliance for encryption of network communications are provided in a dedicated appendix of the Oracle Advanced Security Administrator's Guide.

All cipher suites listed above include FIPS 140-2 validated algorithms available for data encryption.

Encryption of data stored within the database is available only in Oracle versions 11.1 and later. View Data Encryption and Integrity in the Oracle Advanced Security Administration Guide for configuration details. 

Note: FIPS 140-2 compliance or non-compliance for the host and network is outside the purview of the Database STIG. FIPS 140-2 non-compliance at the host/network level does not negate this requirement."
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-26268r2_chk'
  tag severity: 'medium'
  tag gid: 'V-43137'
  tag rid: 'SV-55867r1_rule'
  tag stig_id: 'DG0025-ORACLE11'
  tag gtitle: 'DBMS encryption compliance'
  tag fix_id: 'F-22674r3_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Database Administrator']
  tag ia_controls: 'DCNR-1'
end
