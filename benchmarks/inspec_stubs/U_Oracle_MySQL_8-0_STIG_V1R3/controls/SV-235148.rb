control 'SV-235148' do
  title 'The MySQL Database Server 8.0 must use NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data. Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the Database Management System (DBMS).

Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 or 140-3 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.  

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

The standard for validating cryptographic modules will transition to the NIST FIPS 140-3 publication.

FIPS 140-2 modules can remain active for up to five years after validation or until September 21, 2026, when the FIPS 140-2 validations will be moved to the historical list. Even on the historical list, CMVP supports the purchase and use of these modules for existing systems. While Federal Agencies decide when they move to FIPS 140-3 only modules, purchasers are reminded that for several years there may be a limited selection of FIPS 140-3 modules from which to choose. CMVP recommends purchasers consider all modules that appear on the Validated Modules Search Page:
https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules

More information on the FIPS 140-3 transition can be found here: 
https://csrc.nist.gov/Projects/fips-140-3-transition-effort/'
  desc 'check', %q(Review DBMS configuration to verify it is using NIST FIPS validated cryptographic modules for cryptographic operations.

To check for FIPS validated cryptographic modules for all operations, run this script in the database: 
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables where variable_name = 'ssl_fips_mode';

The result will be either "ON" or "STRICT". If not, then NIST FIPS validated modules are not being used, and this is a finding.)
  desc 'fix', 'Utilize NIST FIPS validated cryptographic modules for all cryptographic operations.
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
  tag check_id: 'C-38367r863349_chk'
  tag severity: 'high'
  tag gid: 'V-235148'
  tag rid: 'SV-235148r863351_rule'
  tag stig_id: 'MYS8-00-006200'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-38330r863350_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
