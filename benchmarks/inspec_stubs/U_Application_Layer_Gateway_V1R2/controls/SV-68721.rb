control 'SV-68721' do
  title 'The ALG that is part of a CDS, when transferring information between different security domains, must examine the information for the presence of organization-defined unsanctioned information.'
  desc 'Without the capability to examine information, there is no means to determine the presence of information not authorized for transfer. Information flow decisions based on unexamined data may allow unintended and unauthorized data flows and therefore risk the confidentiality of information and may also result in the unauthorized release (spillage) of information.

Detection of unsanctioned information includes, for example, checking all information to be transferred for malicious code and key words which may indicate an OPSEC violation.

Organization-defined unsanctioned information depends on the environment, data, and security boundaries of the specific CDS. Organizations implementing CDS must follow the DoD-required process of testing, baselining, and risk assessment to ensure the rigor and accuracy necessary to rely upon a CDS for cross domain security.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG when transferring information between different security domains, is configured to examine the information for the presence of organization-defined unsanctioned information.

If the ALG is not configured to examine the information for the presence of organization-defined unsanctioned information when transferring information between different security domains, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to examine the information for the presence of organization-defined unsanctioned information when transferring information between different security domains.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55091r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54475'
  tag rid: 'SV-68721r1_rule'
  tag stig_id: 'SRG-NET-000284-ALG-000073'
  tag gtitle: 'SRG-NET-000284-ALG-000073'
  tag fix_id: 'F-59329r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001373']
  tag nist: ['CM-6 b', 'AC-4 (15)']
end
