control 'SV-233211' do
  title 'The container platform must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data and images. The container platform must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Review documentation to verify that the container platform is using NSA-approved cryptography to protect classified data and applications. 

If the container platform is not using NSA-approved cryptography for classified data and applications, this is a finding.'
  desc 'fix', 'Configure the container platform to utilize NSA-approved cryptography to protect classified information.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36147r601811_chk'
  tag severity: 'medium'
  tag gid: 'V-233211'
  tag rid: 'SV-233211r879887_rule'
  tag stig_id: 'SRG-APP-000416-CTR-001015'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-36115r601121_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
