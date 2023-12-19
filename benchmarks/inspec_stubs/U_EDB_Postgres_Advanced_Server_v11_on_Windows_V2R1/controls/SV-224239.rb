control 'SV-224239' do
  title 'The EDB Postgres Advanced Server must implement NIST FIPS 140-2 validated cryptographic modules to provision digital signatures.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance of testing and validation.

For detailed information, refer to NIST FIPS Publication 140-2, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', 'If any uncommented lines in <postgresql data dir>\\pg_hba.conf do not start with "hostssl", this is a finding.

The "ssleay32_dll" and "libeay32.dll" files in <EDB Postgres Advanced Server Home>\\bin should be FIPS 140-2 compliant DLLs from EnterpriseDB. These are included in EDB Postgres Advanced Server v11 update 6 (i.e., 11.6) and greater.
If the installed EDB v11 is not update 11.6 or greater, this is a finding.

If C:\\usr\\local\\ssl\\openssl.cnf does not exist with these contents, or if an System Environment variable called OPENSSL_CONF pointing to a file with these contents has not been created, this is a finding:

HOME = .
RANDFILE = $ENV::HOME/.rnd
openssl_conf=openssl_conf_section
[openssl_conf_section]
alg_section=evp_settings
[evp_settings]
fips_mode=yes'
  desc 'fix', 'Edit <postgresql data dir>\\pg_hba.conf so that each uncommented line starts with "hostssl".

If the EDB Postgres Advanced Server minor version is less than version 11.6, install the 11.6 update or later version or contact EnterpriseDB to obtain a copy of the FIPS 140-2 compliant versions of the "ssleay32.dll" and "libeay32.dll" files and replace the "ssleay32.dll" and "libeay32.dll" files in <EDB Postgres Advanced Server Home>\\bin with FIPS 140-2 compliant DLLs from EnterpriseDB. If the EDB Postgres Advanced Server minor version is 11.6 or greater, the FIPS 140-2 compliant versions of these DLLs are installed by default and do not need to be replaced.

Create C:\\usr\\local\\ssl\\openssl.cnf or another file referenced by a System Environment variable called OPENSSL_CONF with these contents:

HOME = .
RANDFILE = $ENV::HOME/.rnd
openssl_conf=openssl_conf_section
[openssl_conf_section]
alg_section=evp_settings
[evp_settings]
fips_mode=yes

Restart the Postgres server via the Services administration GUI.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25912r495734_chk'
  tag severity: 'medium'
  tag gid: 'V-224239'
  tag rid: 'SV-224239r508023_rule'
  tag stig_id: 'EP11-00-012700'
  tag gtitle: 'SRG-APP-000514-DB-000381'
  tag fix_id: 'F-25900r495735_fix'
  tag 'documentable'
  tag legacy: ['V-100503', 'SV-109607']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
