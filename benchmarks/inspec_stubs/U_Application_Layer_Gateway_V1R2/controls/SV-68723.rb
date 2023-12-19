control 'SV-68723' do
  title 'The ALG that is part of a CDS must prohibit the transfer of unsanctioned information in accordance with the security policy when transferring information between different security domains.'
  desc 'The ability to prohibit information transfer is fundamentally necessary to prevent unintended and unauthorized data flows. Failure to prohibit information transfer when necessary will risk the confidentiality of information and may also result in the unauthorized release (spillage) of information.

Detection of unsanctioned information includes, for example, checking all information to be transferred for malicious code and key words which may indicate an OPSEC violation.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG prohibits the transfer of unsanctioned information in accordance with the security policy when transferring information between different security domains.

If the ALG is not configured to prohibit the transfer of unsanctioned information in accordance with the security policy when transferring information between different security domains, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to prohibit the transfer of unsanctioned information in accordance with the security policy when transferring information between different security domains.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55093r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54477'
  tag rid: 'SV-68723r1_rule'
  tag stig_id: 'SRG-NET-000285-ALG-000074'
  tag gtitle: 'SRG-NET-000285-ALG-000074'
  tag fix_id: 'F-59331r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001374']
  tag nist: ['CM-6 b', 'AC-4 (15)']
end
