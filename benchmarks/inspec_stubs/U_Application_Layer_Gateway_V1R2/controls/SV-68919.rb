control 'SV-68919' do
  title 'The ALG providing content filtering must continuously monitor inbound communications traffic crossing internal security boundaries for unusual or unauthorized activities or conditions.'
  desc 'If inbound communications traffic is not continuously monitored, hostile activity may not be detected and prevented. Output from application and traffic monitoring serves as input to continuous monitoring and incident response programs.

Internal monitoring includes the observation of events occurring on the network crosses internal boundaries at managed interfaces such as web content filters. Depending on the type of ALG, organizations can monitor information systems by monitoring audit activities, application access patterns, characteristics of access, content filtering, or unauthorized exporting of information across boundaries. Unusual/unauthorized activities or conditions may include large file transfers, long-time persistent connections, unusual protocols and ports in use, and attempted communications with suspected malicious external addresses.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functions, this is not applicable.

Verify the ALG continuously monitors inbound communications traffic for unusual or unauthorized activities or conditions.

If the ALG does not continuously monitor inbound communications traffic for unusual or unauthorized activities or conditions, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to continuously monitor inbound communications traffic for unusual or unauthorized activities or conditions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55293r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54673'
  tag rid: 'SV-68919r1_rule'
  tag stig_id: 'SRG-NET-000390-ALG-000139'
  tag gtitle: 'SRG-NET-000390-ALG-000139'
  tag fix_id: 'F-59529r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002661']
  tag nist: ['SI-4 (4) (b)']
end
