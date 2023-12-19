control 'SV-214117' do
  title 'PostgreSQL must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to generate and validate cryptographic hashes.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

For detailed information, refer to NIST FIPS Publication 140-3, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', 'First, as the system administrator, run the following to see if FIPS is enabled:

$ cat /proc/sys/crypto/fips_enabled

If fips_enabled is not 1, this is a finding.'
  desc 'fix', 'If fips_enabled = 0, configure OpenSSL to be FIPS compliant.

Configure per operating system documentation: 
RedHat: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-federal_standards_and_regulations
Ubuntu: https://security-certs.docs.ubuntu.com/en/fips

For information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G.'
  impact 0.7
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15333r360982_chk'
  tag severity: 'high'
  tag gid: 'V-214117'
  tag rid: 'SV-214117r836920_rule'
  tag stig_id: 'PGS9-00-008000'
  tag gtitle: 'SRG-APP-000514-DB-000381'
  tag fix_id: 'F-15331r836919_fix'
  tag 'documentable'
  tag legacy: ['SV-87641', 'V-72989']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
