control 'SV-95471' do
  title 'The SDN controller must be configured to produce audit records containing information to establish when the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. In order to compile an accurate risk assessment, and provide forensic analysis of network traffic patterns, it is essential for security personnel to know when (i.e., date and time) flow control events occurred within the infrastructure.'
  desc 'check', 'Review the SDN controller configuration to determine if the audit records will note the date and time of the event that is being logged. 

If the SDN controller is not configured to produce audit records containing information to establish when (i.e., date and time) the events occurred, this is a finding.'
  desc 'fix', 'Configure the SDN controller to include the date and time in the log records.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80497r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80761'
  tag rid: 'SV-95471r1_rule'
  tag stig_id: 'SRG-NET-000075-SDN-000125'
  tag gtitle: 'SRG-NET-000075'
  tag fix_id: 'F-87615r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
