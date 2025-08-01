control 'SV-253773' do
  title 'MariaDB must implement NIST FIPS 140-2 validated cryptographic modules to provision digital signatures.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

For detailed information, refer to NIST FIPS Publication 140-2, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', "As the system administrator, run the following at the Linux commands:
 
# openssl version
OpenSSL 1.0.2k-fips  26 Jan 2017

If fips is not included in the openssl version, this is a finding. 

# sysctl crypto.fips_enabled
crypto.fips_enabled = 1
 
If crypto.fips_enabled = 0, this is a finding. 
 
MariaDB> SHOW GLOBAL VARIABLES LIKE ‘%have_openssl%';

If the value of have_openssl is not YES, this is a finding.

MariaDB> SHOW GLOBAL VARIABLES LIKE ‘%version_ssl_library%';

If the value of version_ssl_library does not contain fips, this is a finding.

Examine the application's code to ensure is does not make calls using libmysqlclient.  
If code uses libmysqlclient  this is a finding."
  desc 'fix', 'If crypto.fips_enabled = 0, configure operating system per operating system documentation: 
RedHat: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-federal_standards_and_regulations
Ubuntu: https://security-certs.docs.ubuntu.com/en/fips'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57225r841842_chk'
  tag severity: 'medium'
  tag gid: 'V-253773'
  tag rid: 'SV-253773r841844_rule'
  tag stig_id: 'MADB-10-012100'
  tag gtitle: 'SRG-APP-000514-DB-000381'
  tag fix_id: 'F-57176r841843_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
