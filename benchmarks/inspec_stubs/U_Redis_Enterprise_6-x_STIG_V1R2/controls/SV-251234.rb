control 'SV-251234' do
  title 'Redis Enterprise DBMS must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the data owners requirements.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated. 

It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

For detailed information, refer to NIST FIPS Publication 140-2 or Publication 140-3, Security Requirements for Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant.

The DBMS relies on the underlying Linux operating system to meet this check."
  desc 'check', 'Verify the operating system implements FIPS compliant cryptographic modules.

As the system administrator, run the following to determine if FIPS is enabled:
# cat /proc/sys/crypto/fips_enabled

If fips_enabled is not 1, this is a finding.'
  desc 'fix', 'To configure the  operating system to implement DoD-approved encryption, review the official RHEL Documentation: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-federal_standards_and_regulations'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54669r863370_chk'
  tag severity: 'medium'
  tag gid: 'V-251234'
  tag rid: 'SV-251234r863371_rule'
  tag stig_id: 'RD6X-00-010000'
  tag gtitle: 'SRG-APP-000514-DB-000383'
  tag fix_id: 'F-54623r804891_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
