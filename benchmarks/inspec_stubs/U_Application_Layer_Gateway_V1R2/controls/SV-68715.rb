control 'SV-68715' do
  title 'The ALG that is part of a CDS, when transferring information between different security domains, must use organization-defined data type identifiers to validate data essential for information flow decisions.'
  desc 'Information flow decisions based on invalid data may allow unintended and unauthorized data flows, and therefore risk the confidentiality of information. They may also result in the unauthorized release (spill) of information.

Data type identifiers include, for example, file names, file types, file signatures/tokens, and multiple internal file signatures/tokens. Information systems may allow transfer of data only if compliant with data type format specifications.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG is configured to use organization-defined data type identifiers to validate data essential for information flow decisions.

If the ALG is not configured to use organization-defined data type identifiers to validate data essential for information flow decisions, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to use organization-defined data type identifiers to validate data essential for information flow decisions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55085r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54469'
  tag rid: 'SV-68715r1_rule'
  tag stig_id: 'SRG-NET-000324-ALG-000070'
  tag gtitle: 'SRG-NET-000324-ALG-000070'
  tag fix_id: 'F-59323r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002201']
  tag nist: ['CM-6 b', 'AC-4 (12)']
end
