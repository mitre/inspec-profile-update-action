control 'SV-235138' do
  title 'If passwords are used for authentication, the MySQL Database Server 8.0 must store only hashed, salted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires Authorizing Official (AO) approval.

In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to the Database Management System (DBMS).

To prevent the compromise of authentication information, such as passwords and PINs, during the authentication process, the feedback from the information system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism.

Obfuscation of user-provided information when typed into the system is a method used in addressing this risk.

For example, displaying asterisks when a user types in a password or PIN, is an example of obscuring feedback of authentication information.

The password requirement is applicable when caching_sha2_password, sha2_password, native_mysql, or LDAP user/password authentication is enabled. When this is the case, password-authenticated accounts can be created in, and authenticated by, the MySQL Server. Other STIG requirements prohibit the use of password-based authentication except when justified and approved. This deals with the exceptions.

The mysql, mysqlsh, and other command-line tools are part of most MySQL installations. These tools can accept a plain-text password, but do offer alternative techniques. Since the typical user of these tools is a Database Administrator (DBA), the consequences of password compromise are particularly serious. Therefore, the use of plain-text passwords must be prohibited as a matter of practice and procedure.'
  desc 'check', "MySQL stores and displays its user passwords in encrypted form. Nevertheless, this should be verified by reviewing the relevant system views, along with the other items to be checked here.

Ask the DBA to review the list of DBMS database objects, database configuration files, associated scripts, and applications defined within, and external to, the DBMS that accesses the database. The list must also include files, tables, or settings used to configure the operational environment for the DBMS and for interactive DBMS user accounts.

Ask the DBA and/or Information System Security Officer (ISSO) to determine if any DBMS database objects, database configuration files, associated scripts, and applications defined within or external to the DBMS that access the database, and DBMS/user environment files/settings/tables, contain database passwords. If any do, confirm that DBMS passwords stored internally or externally to the DBMS are encoded or encrypted.

If any passwords are stored in clear text, this is a finding.

Ask the DBA/System Administrator (SA)/Application Support staff if they have created an external password store for applications, batch jobs, and scripts to use. Verify that all passwords stored there are encrypted.

If a password store is used and any password is not encrypted, this is a finding.

Run this query to determine which MySQL Server authentication methods are enabled:
SELECT PLUGIN_NAME, PLUGIN_STATUS
       FROM INFORMATION_SCHEMA.PLUGINS
       WHERE PLUGIN_NAME LIKE '%ldap%' OR 
       PLUGIN_NAME LIKE '%ldap%' OR 
       PLUGIN_NAME LIKE '%pam%' OR 
       PLUGIN_NAME like '%password';

If the results return any of the following values:
'mysql_native_password','ACTIVE'
'sha256_password','ACTIVE'
'caching_sha2_password’,’ACTIVE’

Next, determine if any accounts have been created that use passwords.
SELECT user, host,
    `user`.`plugin`
FROM `mysql`.`user` where 
(user.plugin like '%password') 
AND NOT
(user like 'mysql.%' or user ='root');

For the mysql or mysqlsh command line tools, which can be configured to accept a plain-text password, and any other essential tool with the same limitation, verify that the system documentation explains the need for the tool, who uses it, and any relevant mitigations; and that AO approval has been obtained; if not, this is a finding.

Request evidence that all users of the tool are trained in the importance of not using the plain-text password option; how to keep the password hidden; and adherence to this practice. If they are not, this is a finding."
  desc 'fix', "Develop, document, and maintain a list of DBMS database objects, database configuration files, associated scripts, and applications defined within or external to the DBMS that access the database, and DBMS/user environment files/settings in the System Security Plan.

Record whether they do or do not contain DBMS passwords. If passwords are present, ensure they are encoded or encrypted and protected by host system security.

Where possible, alter the authentication mode to X509 or LDAP SASL/Kerberos:
Just X509 certificate - for example
ALTER USER 'jeffrey'@'localhost' REQUIRE X509;

Specific X509 - for example
ALTER USER 'jeffrey'@'localhost'
  REQUIRE SUBJECT '/C=SE/ST=Stockholm/L=Stockholm/
    O=MySQL demo client certificate/
    CN=client/emailAddress=client@example.com'
  AND ISSUER '/C=SE/ST=Stockholm/L=Stockholm/
    O=MySQL/CN=CA/emailAddress=ca@example.com'
AND CIPHER 'EDH-RSA-DES-CBC3-SHA’;

LDAP SASL Example
CREATE USER 'boris'@'localhost'
  IDENTIFIED WITH authentication_ldap_sasl
  AS 'uid=boris_ldap,ou=People,dc=example,dc=com';

If password authentication is necessary, then for mysql and mysqlsh command lines which cannot be configured not to accept a plain-text password when mixed-mode authentication is enabled, and any other essential tool with the same limitation:
1) Document the need for it, who uses it, any relevant mitigations, and obtain AO approval.
2) Train all users of the tool in the importance of not using the plain-text password option and in how to keep the password hidden."
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38357r623534_chk'
  tag severity: 'medium'
  tag gid: 'V-235138'
  tag rid: 'SV-235138r623536_rule'
  tag stig_id: 'MYS8-00-005100'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag fix_id: 'F-38320r623535_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
