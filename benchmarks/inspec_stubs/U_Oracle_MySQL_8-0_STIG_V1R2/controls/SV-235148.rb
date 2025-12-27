control 'SV-235148' do
  title 'The MySQL Database Server 8.0 must use NIST FIPS 140-2 validated cryptographic modules for cryptographic operations.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data. Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the Database Management System (DBMS).

Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.  

The security functions validated as part of FIPS 140-2 for cryptographic modules are described in FIPS 140-2 Annex A.

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.'
  desc 'check', %q(Review DBMS configuration to verify it is using NIST FIPS 140-2 validated cryptographic modules for cryptographic operations.

To check for FIPS validated cryptographic modules for all operations, run this script in the database: 
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables where variable_name = 'ssl_fips_mode';

The result will be either "ON" or "STRICT". If not, then NIST FIPS 140-2 validated modules are not being used, and this is a finding.)
  desc 'fix', 'Utilize NIST FIPS 140-2 validated cryptographic modules for all cryptographic operations.
See Use MySQL Server OpenSSL FIPS mode. See https://dev.mysql.com/doc/refman/8.0/en/fips-mode.html

Turn on MySQL FIPS mode and restart mysqld
Edit my.cnf
[mysqld]
ssl_fips_mode=ON

or
[mysqld]
ssl_fips_mode=STRICT

ON: Enable FIPS mode.
STRICT: Enable “strict” FIPS mode.'
  impact 0.7
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38367r623564_chk'
  tag severity: 'high'
  tag gid: 'V-235148'
  tag rid: 'SV-235148r623566_rule'
  tag stig_id: 'MYS8-00-006200'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-38330r623565_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
