control 'SV-68909' do
  title 'The ALG providing content filtering must send an immediate (within seconds) alert to the system administrator, at a minimum, in response to malicious code detection.'
  desc 'Without an alert, security personnel may be unaware of an impending failure of the audit capability; then the ability to perform forensic analysis and detect rate-based and other anomalies will be impeded.

The ALG generates an immediate (within seconds) alert which notifies designated personnel of the incident. Sending a message to an unattended log or console does not meet this requirement since that will not be seen immediately. These messages should include a severity level indicator or code as an indicator of the criticality of the incident.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functionality, this is not applicable.

Verify the ALG sends an immediate (within seconds) alert to the system administrator, at a minimum, when malicious code is detected.

If the ALG does not send an immediate (within seconds) alert to the system administrator, at a minimum, when malicious code is detected, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to send an immediate (within seconds) alert to the system administrator, at a minimum, when malicious code is detected.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55283r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54663'
  tag rid: 'SV-68909r1_rule'
  tag stig_id: 'SRG-NET-000249-ALG-000146'
  tag gtitle: 'SRG-NET-000249-ALG-000146'
  tag fix_id: 'F-59519r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
