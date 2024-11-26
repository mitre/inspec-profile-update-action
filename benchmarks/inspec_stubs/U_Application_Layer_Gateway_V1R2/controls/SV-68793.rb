control 'SV-68793' do
  title 'The ALG providing encryption intermediary services must implement NIST FIPS-validated cryptography to generate cryptographic hashes.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

This requirement applies only to ALGs that provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC).'
  desc 'check', 'If the ALG does not provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC), this is not applicable.

Verify the ALG implements NIST FIPS-validated cryptography to generate cryptographic hashes.

If the ALG does not implement NIST FIPS-validated cryptography to generate cryptographic hashes, this is a finding'
  desc 'fix', 'If encryption intermediary services are provided, configure the ALG to implement NIST FIPS-validated cryptography to generate cryptographic hashes.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55163r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54547'
  tag rid: 'SV-68793r1_rule'
  tag stig_id: 'SRG-NET-000510-ALG-000025'
  tag gtitle: 'SRG-NET-000510-ALG-000025'
  tag fix_id: 'F-59401r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
