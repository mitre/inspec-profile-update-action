control 'SV-95475' do
  title 'The SDN controller must be configured to produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. In order to compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source (i.e. service, function, node name, IP address, etc.) of the event.'
  desc 'check', 'Review the SDN controller configuration to determine if the audit records will note the source (e.g., flow, API, IP address, etc.) the event that is being logged. 

If the SDN controller is not configured to produce audit records containing information to establish the source (e.g., flow, API, IP address, etc.) of the events, this is a finding.'
  desc 'fix', 'Configure the SDN controller to include the source (e.g., flow, API, IP address, etc.) of the event in the log records.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80501r2_chk'
  tag severity: 'medium'
  tag gid: 'V-80765'
  tag rid: 'SV-95475r1_rule'
  tag stig_id: 'SRG-NET-000077-SDN-000135'
  tag gtitle: 'SRG-NET-000077'
  tag fix_id: 'F-87619r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
