control 'SV-68731' do
  title 'The ALG that is part of a CDS, when transferring information between different security domains, must apply the same security policy filtering to metadata as it applies to data payloads.'
  desc 'Subjecting metadata to the same filtering and inspection policies as payload data helps to mitigate the risk of data compromise through covert channels. This security measure also helps prevent the bypassing of security policy filtering.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG is configured to apply the same security policy filtering to metadata as it applies to data payloads when transferring information between different security domains.

If the ALG is not configured to apply the same security policy filtering to metadata as it applies to data payloads when transferring information between different security domains, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to apply the same security policy filtering to metadata as it applies to data payloads when transferring information between different security domains.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55101r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54485'
  tag rid: 'SV-68731r1_rule'
  tag stig_id: 'SRG-NET-000328-ALG-000078'
  tag gtitle: 'SRG-NET-000328-ALG-000078'
  tag fix_id: 'F-59339r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002211']
  tag nist: ['CM-6 b', 'AC-4 (19)']
end
