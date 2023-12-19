control 'SV-68707' do
  title 'The ALG that provides intermediary services for HTTP must inspect inbound and outbound HTTP traffic for protocol compliance and protocol anomalies.'
  desc 'Application protocol anomaly detection examines application layer protocols such as HTTP to identify attacks based on observed deviations in the normal RFC behavior of a protocol or service. This type of monitoring allows for the detection of known and unknown exploits which exploit weaknesses of commonly used protocols.

Since protocol anomaly analysis examines the application payload for patterns or anomalies, an HTTP proxy must be included in the ALG. This ALG will be configured to inspect inbound and outbound HTTP communications traffic to detect protocol anomalies such as malformed message and command insertion attacks. 

All inbound and outbound traffic, including HTTPS, must be inspected. However, the intention of this policy is not to mandate HTTPS inspection by the ALG. Typically, HTTPS traffic is inspected either at the source, destination and/or is directed for inspection by organizationally-defined network termination point.'
  desc 'check', 'If the ALG does not provide intermediary/proxy services for HTTP communications traffic, this is not applicable.

Verify the ALG inspects inbound and outbound HTTP communications traffic for protocol compliance and protocol anomalies.

If the ALG does not inspect inbound and outbound HTTP communications traffic for protocol compliance and protocol anomalies, this is a finding.'
  desc 'fix', 'If the ALG provides intermediary/proxy services for HTTP communications traffic, configure the ALG to inspect inbound and outbound HTTP communications traffic for protocol compliance and protocol anomalies.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55077r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54461'
  tag rid: 'SV-68707r1_rule'
  tag stig_id: 'SRG-NET-000512-ALG-000066'
  tag gtitle: 'SRG-NET-000512-ALG-000066'
  tag fix_id: 'F-59315r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001125']
  tag nist: ['CM-6 b', 'SC-7 (17)']
end
