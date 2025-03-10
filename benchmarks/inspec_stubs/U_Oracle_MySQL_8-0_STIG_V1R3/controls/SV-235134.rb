control 'SV-235134' do
  title 'The MySQL Database Server 8.0, when utilizing PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

A certificate’s certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.

Database Management Systems that do not validate certificates by performing RFC 5280-compliant certification path validation are in danger of accepting certificates that are invalid and/or counterfeit. This could allow unauthorized access to the database.'
  desc 'check', 'The database supports PKI-based authentication by using digital certificates over TLS in addition to the native encryption and data integrity capabilities of these protocols.

Review MySQL Database Server 8.0 configuration to verify DBMS user account certificates are valid by performing RFC 5280-compliant certification path validation.

Run the following command to determine the certificate in use along with other details:
select @@ssl_ca, @@ssl_capath, @@ssl_cert, @@ssl_cipher, @@ssl_crl, @@ssl_crlpath, @@ssl_fips_mode, @@ssl_key;

If ssl_crl is not set to a CRL file, this is a finding. 

If ssl_crlpath is empty then use the default, which is the datadir path. To get that path run select @@datadir.

Next verify the existence of the CRL file.

If the CRL file does not exist, this is a finding.  

Next, verify that require_secure_transport is ON by running:
select @@require_secure_transport;

If require_secure_transport is not 1 for ON, this is a finding.

If the certificate is not a DoD approved certificate, or if no certificate is listed, this is a finding.

Confirm Issuer and Subject map to the username. Run the following script:
SELECT `user`.`Host`,
    `user`.`User`,
    `user`.`ssl_type`,
    CAST(`user`.`x509_issuer` as CHAR) as Issuer,
    CAST(`user`.`x509_subject` as CHAR) as Subject
FROM `mysql`.`user`;

If user accounts are not being mapped to authenticated identities, this is a finding.'
  desc 'fix', "Configure the DBMS to validate certificates by constructing a certification path with status information to an accepted trust anchor.

Configure the database server to support Transport Layer Security (TLS) protocols.
mysql> set persist require_secure_transport=ON;

Set system variables on the server side specify DoD approved certificate and key files the server uses when permitting clients to establish encrypted connections:

ssl_ca: The path name of the Certificate Authority (CA) certificate file. (ssl_capath is similar but specifies the path name of a directory of CA certificate files.)

ssl_cert: The path name of the server public key certificate file. This certificate can be sent to the client and authenticated against the CA certificate that it has.

ssl_key: The path name of the server private key file.

For example, to enable the server for encrypted connections with certificates, start it with these lines in the my.cnf file, changing the file names as necessary:

[mysqld]
ssl_ca=ca.pem
ssl_cert=server-cert.pem
ssl_key=server-key.pem
Alter users to require X509 certificates

Below is an example to add X509 as a requirement.

For a new user
CREATE USER 'jeffrey'@'localhost' REQUIRE X509;
AND SUBJECT '/C=US/ST=Texas/L=Houston/O=SomeCompany/CN=Johan Smith'
  AND ISSUER '/C=US/ST=Texas/L=Houston/O=SomeCompany/CN=Some CA';

Or to add to an existing user
ALTER USER 'johansmith'@'%'
REQUIRE X509
  AND SUBJECT '/C=US/ST=Texas/L=Houston/O=SomeCompany/CN=Johan Smith'
  AND ISSUER '/C=US/ST=Texas/L=Houston/O=SomeCompany/CN=Some CA';"
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38353r623522_chk'
  tag severity: 'medium'
  tag gid: 'V-235134'
  tag rid: 'SV-235134r623524_rule'
  tag stig_id: 'MYS8-00-004700'
  tag gtitle: 'SRG-APP-000175-DB-000067'
  tag fix_id: 'F-38316r623523_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
