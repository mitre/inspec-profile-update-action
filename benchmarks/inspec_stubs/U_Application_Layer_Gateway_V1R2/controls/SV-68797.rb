control 'SV-68797' do
  title 'The ALG providing encryption intermediary services must use NIST FIPS-validated cryptography to implement encryption services.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

This requirement applies only to ALGs that provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC).'
  desc 'check', 'If the ALG does not provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC), this is not applicable.

Verify the ALG uses NIST FIPS-validated cryptography to implement encryption services.

If the ALG does not use NIST FIPS-validated cryptography to implement encryption services, this is a finding.'
  desc 'fix', 'If encryption intermediary services are provided, configure the ALG to use NIST FIPS-validated cryptography to implement encryption services.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55167r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54551'
  tag rid: 'SV-68797r1_rule'
  tag stig_id: 'SRG-NET-000510-ALG-000111'
  tag gtitle: 'SRG-NET-000510-ALG-000111'
  tag fix_id: 'F-59405r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
