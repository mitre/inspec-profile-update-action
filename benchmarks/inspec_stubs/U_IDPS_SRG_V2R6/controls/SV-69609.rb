control 'SV-69609' do
  title 'The IDPS must send an immediate (within seconds) alert to, at a minimum, the system administrator when malicious code is detected.'
  desc 'Without an alert, security personnel may be unaware of an impending failure of the audit capability, and the ability to perform forensic analysis and detect rate-based and other anomalies will be impeded.

The IDPS generates an immediate (within seconds) alert which notifies designated personnel of the incident. Sending a message to an unattended log or console does not meet this requirement since that will not be seen immediately. These messages should include a severity level indicator or code as an indicator of the criticality of the incident.'
  desc 'check', 'Verify the IDPS sends an immediate (within seconds) alert to, at a minimum, the system administrator when malicious code is detected.

If the IDPS does not send an immediate (within seconds) alert to, at a minimum, the system administrator when malicious code is detected, this is a finding.'
  desc 'fix', 'Configure the IDPS to send an immediate (within seconds) alert to, at a minimum, the system administrator when malicious code is detected.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55987r2_chk'
  tag severity: 'medium'
  tag gid: 'V-55363'
  tag rid: 'SV-69609r2_rule'
  tag stig_id: 'SRG-NET-000249-IDPS-00222'
  tag gtitle: 'SRG-NET-000249-IDPS-00222'
  tag fix_id: 'F-60461r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
