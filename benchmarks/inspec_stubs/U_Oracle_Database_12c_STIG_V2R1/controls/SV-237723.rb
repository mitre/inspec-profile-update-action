control 'SV-237723' do
  title 'The DBMS must use multifactor authentication for access to user accounts.'
  desc "Multifactor authentication is defined as using two or more factors to achieve authentication.

Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or
(iii) Something a user is (e.g., biometric).

The DBMS must be configured to automatically utilize organization-level account management functions, and these functions must immediately enforce the organization's current account policy. 


The lack of multifactor authentication makes it much easier for an attacker to gain unauthorized access to a system.

Transport Layer Security (TLS) is the successor protocol to Secure Sockets Layer (SSL). Although the Oracle configuration parameters have names including 'SSL', such as SSL_VERSION and SSL_CIPHER_SUITES, they refer to TLS.
Use authentication to prove the identities of users who are attempting to log on to the database. Oracle Database enables strong authentication with Oracle authentication adapters that support various third-party authentication services, including TLS with digital certificates, as well as Smart Cards (CAC, PIV)."
  desc 'check', 'If all user accounts are authenticated by the organization-level authentication/access mechanism and not by the DBMS, this is not a finding.

Review DBMS settings, OS settings, and/or enterprise-level authentication/access mechanism settings to determine whether user accounts are required to use multifactor authentication.

If user accounts are not required to use multifactor authentication, this is a finding.

If the $ORACLE_HOME/network/admin/sqlnet.ora contains entries similar to the following, TLS is enabled. (Note: This assumes that a single sqlnet.ora file, in the default location, is in use. Please see the supplemental file "Non-default sqlnet.ora configurations.pdf" for how to find multiple and/or differently located sqlnet.ora files.)

SQLNET.AUTHENTICATION_SERVICES= (BEQ, TCPS)
SSL_VERSION = 1.2
SSL_CLIENT_AUTHENTICATION = TRUE
WALLET_LOCATION =
(SOURCE =
(METHOD = FILE)
(METHOD_DATA =
(DIRECTORY = /u01/app/oracle/product/12.1.0/dbhome_1/owm/wallets)
)
)

SSL_CIPHER_SUITES= (SSL_RSA_WITH_AES_256_CBC_SHA384)
ADR_BASE = /u01/app/oracle'
  desc 'fix', 'Configure DBMS, OS and/or enterprise-level authentication/access mechanism to require multifactor authentication for user accounts.

If appropriate, enable support for Transport Layer Security (TLS) protocols and multifactor authentication through the use of Smart Cards (CAC/PIV).
Oracle Database is capable of being configured to integrate users with an enterprise-level authentication/access mechanism.
 
The directions are in the Oracle Database Security Guide, Section 6

https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/database-security-guide.pdf#page=318

This section will give detailed step-by-step directions to configure authentication using PKI Certificates for centrally managed users by configuring Secure Sockets Layer in the Oracle database and integrating with LDAP.'
  impact 0.7
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40942r667199_chk'
  tag severity: 'high'
  tag gid: 'V-237723'
  tag rid: 'SV-237723r667201_rule'
  tag stig_id: 'O121-C2-012900'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-40905r667200_fix'
  tag 'documentable'
  tag legacy: ['V-61703', 'SV-76193']
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)']
end
