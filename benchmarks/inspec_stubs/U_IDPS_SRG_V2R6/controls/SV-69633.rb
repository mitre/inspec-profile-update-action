control 'SV-69633' do
  title 'The IDPS must send an alert to, at a minimum, the ISSM and ISSO when threats identified by authoritative sources (e.g., IAVMs or CTOs) are detected which indicate a compromise or potential for compromise.'
  desc 'Without an alert, security personnel may be unaware of an impending failure of the audit capability, and the ability to perform forensic analysis and detect rate-based and other anomalies will be impeded.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The IDPS must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. The ISSM or ISSO may designate the system administrator or other authorized personnel to receive the alert within the specified time, validate the alert, then forward only validated alerts to the ISSM and ISSO.'
  desc 'check', 'Verify the IDPS sends an alert to, at a minimum, the ISSM and ISSO when threats identified by authoritative sources (e.g., IAVMs or CTOs) are detected which indicate a compromise or potential for compromise.

If the IDPS does not send an alert to, at a minimum, the ISSM and ISSO when threats identified by authoritative sources (e.g., IAVMs or CTOs) are detected which indicate a compromise or potential for compromise, this is a finding.'
  desc 'fix', 'Configure the IDPS to send an alert to, at a minimum, the ISSM and ISSO when threats identified by authoritative sources (e.g., IAVMs or CTOs) are detected which indicate a compromise or potential for compromise.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-56003r3_chk'
  tag severity: 'medium'
  tag gid: 'V-55387'
  tag rid: 'SV-69633r3_rule'
  tag stig_id: 'SRG-NET-000392-IDPS-00215'
  tag gtitle: 'SRG-NET-000392-IDPS-00215'
  tag fix_id: 'F-60253r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
