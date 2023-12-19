control 'SV-224242' do
  title 'The EDB Postgres Advanced Server must be configured on a platform that has a NIST certified FIPS 140-2 or 140-3 installation of OpenSSL.'
  desc %q(Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data. Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the DBMS.

Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 or 140-3 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. 

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

The standard for validating cryptographic modules will transition to the NIST FIPS 140-3 publication.

FIPS 140-2 modules can remain active for up to 5 years after validation or until September 21, 2026, when the FIPS 140-2 validations will be moved to the historical list.  Even on the historical list, CMVP supports the purchase and use of these modules for existing systems. While Federal Agencies decide when they move to FIPS 140-3 only modules, purchasers are reminded that for several years there may be a limited selection of FIPS 140-3 modules from which to choose. CMVP recommends purchasers consider all modules that appear on the Validated Modules Search Page:
https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules

More information on the FIPS 140-3 transition can be found here: 
https://csrc.nist.gov/Projects/fips-140-3-transition-effort/

When the EDB FIPS 140 certified cryptographic modules are configured properly, an EDB Postgres Advanced Server will fail to start if non-FIPS 140 ciphers are specified for the Postgres ssl_ciphers parameter. To test whether the FIPS 140 compliant configuration is working, temporarily set the "ssl_ciphers" parameter in the postgresql.conf file to 'RC4-SHA' and then attempt to restart the database service. Since "RC4-SHA" is not a FIPS 140 approved cipher, the database will fail to start. Using the Event Viewer in Windows, a "FATAL: could not set the cipher list (no valid ciphers available)" error will be found under "Event Viewer (Local) >> Windows Logs >> Application".

)
  desc 'check', 'If any uncommented lines in <postgresql data dir>\\pg_hba.conf do not start with "hostssl", this is a finding.

The "ssleay32_dll" and "libeay32.dll" files in <EDB Postgres Advanced Server Home>\\bin should be FIPS 140-2 or 140-3 compliant DLLs from EnterpriseDB. These are included in EDB Postgres Advanced Server v11 update 6 (i.e., 11.6) and greater.
If the installed EDB v11 is not update 11.6 or greater, this is a finding.

If C:\\usr\\local\\ssl\\openssl.cnf does not exist with these contents, or if an System Environment variable called OPENSSL_CONF pointing to a file with these contents has not been created, this is a finding:

HOME = .
RANDFILE = $ENV::HOME/.rnd
openssl_conf=openssl_conf_section
[openssl_conf_section]
alg_section=evp_settings
[evp_settings]
fips_mode=yes'
  desc 'fix', 'Edit <postgresql data dir>\\pg_hba.conf so that each uncommented line starts with "hostssl"

If the EDB Postgres Advanced Server minor version is less than version 11.6, install the 11.6 update or later version or contact EnterpriseDB to obtain a copy of the FIPS 140 compliant versions of the "ssleay32.dll" and "libeay32.dll" files and replace the "ssleay32.dll" and "libeay32.dll" files in <EDB Postgres Advanced Server Home>\\bin with FIPS 140 compliant DLLs from EnterpriseDB. If the EDB Postgres Advanced Server minor version is 11.6 or greater, the FIPS 140 compliant versions of these DLLs are installed by default and do not need to be replaced.

Create C:\\usr\\local\\ssl\\openssl.cnf or another file referenced by a System Environment variable called OPENSSL_CONF with these contents:

HOME = .
RANDFILE = $ENV::HOME/.rnd
openssl_conf=openssl_conf_section
[openssl_conf_section]
alg_section=evp_settings
[evp_settings]
fips_mode=yes

Restart the Postgres server via the Services administration GUI.'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25915r836883_chk'
  tag severity: 'high'
  tag gid: 'V-224242'
  tag rid: 'SV-224242r836885_rule'
  tag stig_id: 'EP11-00-013200'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-25903r836884_fix'
  tag satisfies: ['SRG-APP-000179-DB-000114', 'SRG-APP-000514-DB-000382', 'SRG-APP-000514-DB-000383']
  tag 'documentable'
  tag legacy: ['SV-109617', 'V-100513']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
