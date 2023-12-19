control 'SV-68795' do
  title 'The ALG providing encryption intermediary services must implement NIST FIPS-validated cryptography for digital signatures.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

This requirement applies only to ALGs that provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC).'
  desc 'check', 'If the ALG does not provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC), this is not applicable.

Verify the ALG implements NIST FIPS-validated cryptography to implement for digital signatures.

If the ALG does not implement NIST FIPS-validated cryptography for digital signatures, this is a finding.'
  desc 'fix', 'If encryption intermediary services are provided, configure the ALG to implement NIST FIPS-validated cryptography for digital signatures.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55165r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54549'
  tag rid: 'SV-68795r1_rule'
  tag stig_id: 'SRG-NET-000510-ALG-000040'
  tag gtitle: 'SRG-NET-000510-ALG-000040'
  tag fix_id: 'F-59403r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
