control 'SV-91123' do
  title 'Kona Site Defender providing encryption intermediary services must implement NIST FIPS-validated cryptography to generate cryptographic hashes.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

This requirement applies only to ALGs that provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC).'
  desc 'check', 'Confirm Kona Site Defender only allows NIST SP 800-52 TLS settings:

1. Navigate to the Qualys SSL Scanner: https://www.ssllabs.com/ssltest/analyze.html
2. Enter into the scanner the Hostname being tested.
3. Under the "Configurations" and then "Cipher Suites" section, verify that communications are restricted to NIST FIPS-validated cryptography to generate cryptographic hashes as defined at https://www.nist.gov/publications/guidelines-selection-configuration-and-use-transport-layer-security-tls-implementations?pub_id=915295.

If the cipher suites include non-NIST FIPS-validated cryptography, this is a finding.'
  desc 'fix', 'Configure Kona Site Defender to only allow NIST FIPS-validated cryptography to generate cryptographic hashes:

Contact the Akamai Professional Services team to implement the changes at 1-877-4-AKATEC (1-877-425-2832).'
  impact 0.7
  ref 'DPMS Target Akamai Edge Security ALG'
  tag check_id: 'C-76087r1_chk'
  tag severity: 'high'
  tag gid: 'V-76427'
  tag rid: 'SV-91123r1_rule'
  tag stig_id: 'AKSD-WF-000022'
  tag gtitle: 'SRG-NET-000510-ALG-000025'
  tag fix_id: 'F-83105r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
