control 'SV-68703' do
  title 'The ALG that provides intermediary services for SMTP must inspect inbound and outbound SMTP and Extended SMTP communications traffic for protocol compliance and protocol anomalies.'
  desc 'Application protocol anomaly detection examines application layer protocols such as SMTP to identify attacks based on observed deviations in the normal RFC behavior of a protocol or service. This type of monitoring allows for the detection of known and unknown exploits which exploit weaknesses of commonly used protocols.

Since protocol anomaly analysis examines the application payload for patterns or anomalies, an SMTP proxy must be included in the ALG. This ALG will be configured to inspect inbound and outbound SMTP and Extended SMTP communications traffic to detect protocol anomalies such as malformed message and command insertion attacks.'
  desc 'check', 'If the ALG does not provide intermediary/proxy services for SMTP communications traffic, this is not applicable.

Verify the ALG inspects inbound and outbound SMTP and Extended SMTP communications traffic for protocol compliance and protocol anomalies.

If the ALG does not inspect inbound and outbound SMTP and Extended SMTP communications traffic for protocol compliance and protocol anomalies, this is a finding.'
  desc 'fix', 'If the ALG provides intermediary/proxy services SMTP communications traffic, configure the ALG to inspect inbound and outbound SMTP and Extended SMTP communications traffic for protocol compliance and protocol anomalies.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55073r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54457'
  tag rid: 'SV-68703r1_rule'
  tag stig_id: 'SRG-NET-000512-ALG-000064'
  tag gtitle: 'SRG-NET-000512-ALG-000064'
  tag fix_id: 'F-59311r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001125']
  tag nist: ['CM-6 b', 'SC-7 (17)']
end
