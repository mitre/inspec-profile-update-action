control 'SV-235188' do
  title 'The MySQL Database Server 8.0 must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to provision digital signatures.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

For detailed information, refer to NIST FIPS Publication 140-2 or Publication 140-3, Security Requirements For Cryptographic Modules.  Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', %q(ALL cryptography is provided via OpenSSL and can be verified in FIPS mode. 

Run this command:
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables where variable_name = 'ssl_fips_mode';

If the VARIABLE_VALUE does not return "ON" or "STRICT", this is a finding.

In general, STRICT imposes more restrictions than ON, but MySQL itself has no FIPS-specific code other than to specify to OpenSSL the FIPS mode value. The exact behavior of FIPS mode for ON or STRICT depends on the OpenSSL version.)
  desc 'fix', 'Implement NIST FIPS validated cryptographic modules to provision digital signatures.

Turn on MySQL FIPS mode and restart mysqld
Edit my.cnf
[mysqld]
ssl_fips_mode=ON

or
[mysqld]
ssl_fips_mode=STRICT

In general, STRICT imposes more restrictions than ON, but MySQL itself has no FIPS-specific code other than to specify to OpenSSL the FIPS mode value. The exact behavior of FIPS mode for ON or STRICT depends on the OpenSSL version.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38407r623684_chk'
  tag severity: 'medium'
  tag gid: 'V-235188'
  tag rid: 'SV-235188r863356_rule'
  tag stig_id: 'MYS8-00-011600'
  tag gtitle: 'SRG-APP-000514-DB-000381'
  tag fix_id: 'F-38370r863355_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
