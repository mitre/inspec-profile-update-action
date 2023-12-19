control 'SV-220263' do
  title 'The DBMS, when using PKI-based authentication, must enforce authorized access to the corresponding private key.'
  desc "The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and can pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.

All access to the private key of the DBMS must be restricted to authorized and authenticated users. If unauthorized users have access to the DBMS’s private key, an attacker could gain access to the primary key and use it to impersonate the database on the network.

Transport Layer Security (TLS) is the successor protocol to Secure Sockets Layer (SSL). Although the Oracle configuration parameters have names including 'SSL', such as SSL_VERSION and SSL_CIPHER_SUITES, they refer to TLS."
  desc 'check', 'Review DBMS configuration to determine whether appropriate access controls exist to protect the DBMS’s private key. If strong access controls do not exist to enforce authorized access to the private key, this is a finding.
- - - - -
The database supports authentication by using digital certificates over TLS in addition to the native encryption and data integrity capabilities of these protocols.

An Oracle Wallet is a container that is used to store authentication and signing credentials, including private keys, certificates, and trusted certificates needed by TLS. In an Oracle environment, every entity that communicates over TLS must have a wallet containing an X.509 version 3 certificate, private key, and list of trusted certificates, with the exception of Diffie-Hellman.

If the $ORACLE_HOME/network/admin/sqlnet.ora contains the following entries, TLS is installed. (Note: This assumes that a single sqlnet.ora file, in the default location, is in use. Please see the supplemental file "Non-default sqlnet.ora configurations.pdf" for how to find multiple and/or differently located sqlnet.ora files.)

WALLET_LOCATION = (SOURCE=
                          (METHOD = FILE) 
                          (METHOD_DATA = 
                           DIRECTORY=/wallet)

SSL_CIPHER_SUITES=(SSL_cipher_suiteExample)
SSL_VERSION = 1.2
SSL_CLIENT_AUTHENTICATION=FALSE/TRUE'
  desc 'fix', 'Implement strong access and authentication controls to protect the database’s private key.

Configure the database to support Transport Layer Security (TLS) protocols and the Oracle Wallet to store authentication and signing credentials, including private keys.'
  impact 0.7
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21978r799973_chk'
  tag severity: 'high'
  tag gid: 'V-220263'
  tag rid: 'SV-220263r879613_rule'
  tag stig_id: 'O121-C1-015400'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag fix_id: 'F-21970r391921_fix'
  tag 'documentable'
  tag legacy: ['SV-76033', 'V-61543']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
