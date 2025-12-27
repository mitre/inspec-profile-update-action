control 'SV-213665' do
  title 'The EDB Postgres Advanced Server must implement NIST FIPS 140-2 validated cryptographic modules to generate and validate cryptographic hashes.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

For detailed information, refer to NIST FIPS Publication 140-2, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', 'If a FIPS-certified OpenSSL library is not installed, this is a finding.

Run the command "cat /proc/sys/crypto/fips_enabled". 

If the output is not "1", this is a finding.'
  desc 'fix', 'There is no known fix for a FIPS-compliant OpenSSL library on Microsoft Windows at this time.

Configure RHEL OpenSSL as defined in section 9.1 of the RHEL OpenSSL FIPS Compliance documentation here:

http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140sp/140sp1758.pdf'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14887r290307_chk'
  tag severity: 'high'
  tag gid: 'V-213665'
  tag rid: 'SV-213665r508024_rule'
  tag stig_id: 'PPS9-00-012800'
  tag gtitle: 'SRG-APP-000514-DB-000382'
  tag fix_id: 'F-14885r290308_fix'
  tag 'documentable'
  tag legacy: ['V-69079', 'SV-83683']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
