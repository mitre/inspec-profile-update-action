control 'SV-220292' do
  title 'The DBMS must map the authenticated identity to the user account using PKI-based authentication.'
  desc "The cornerstone of the PKI is the private key used to encrypt or digitally sign information. The key by itself is a cryptographic value that does not contain specific user information.

When including the DBMS in the Private Key Infrastructure, the authenticated user must map directly to a user account in the DBMS. If the user account is not directly tied to the authenticated identity, there is no way to know which, if any, database user account has been authorized.

Transport Layer Security (TLS) is the successor protocol to Secure Sockets Layer (SSL). Although the Oracle configuration parameters have names including 'SSL', such as SSL_VERSION and SSL_CIPHER_SUITES, they refer to TLS."
  desc 'check', 'Review DBMS configuration to verify DBMS user accounts are being mapped directly to authenticated identity information being passed via the PKI.

If user accounts are not being mapped to authenticated identity information being passed via the PKI, this is a finding.

- - - - -
The database supports PKI-based authentication by using digital certificates over TLS in addition to the native encryption and data integrity capabilities of these protocols.

Oracle provides a complete PKI that is based on RSA Security, Inc., Public-Key Cryptography Standards, and which interoperates with Oracle servers and clients.  The database uses a wallet that is a container that is used to store authentication and signing credentials, including private keys, certificates, and trusted certificates needed by TLS. In an Oracle environment, every entity that communicates over TLS must have a wallet containing an X.509 version 3 certificate, private key, and list of trusted certificates.  Security administrators use Oracle Wallet Manager to manage security credentials on the server.

If the $ORACLE_HOME/network/admin/sqlnet.ora contains the following entries, TLS is installed. (Note: This assumes that a single sqlnet.ora file, in the default location, is in use. Please see the supplemental file "Non-default sqlnet.ora configurations.pdf" for how to find multiple and/or differently located sqlnet.ora files.)

WALLET_LOCATION = (SOURCE=
                          (METHOD = FILE) 
                          (METHOD_DATA = 
                           DIRECTORY=/wallet) 

SSL_CIPHER_SUITES=(SSL_cipher_suiteExample) 
SSL_VERSION = 1.2
SSL_CLIENT_AUTHENTICATION=FALSE/TRUE'
  desc 'fix', 'Configure the DBMS to map the authenticated identity directly to the DBMS user account.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22007r392007_chk'
  tag severity: 'medium'
  tag gid: 'V-220292'
  tag rid: 'SV-220292r397600_rule'
  tag stig_id: 'O121-C2-015500'
  tag gtitle: 'SRG-APP-000177-DB-000069'
  tag fix_id: 'F-21999r392008_fix'
  tag 'documentable'
  tag legacy: ['SV-76233', 'V-61743']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
