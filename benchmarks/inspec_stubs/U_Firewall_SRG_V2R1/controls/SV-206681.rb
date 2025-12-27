control 'SV-206681' do
  title 'The firewall must generate traffic log entries containing information to establish the source of the events, such as the source IP address at a minimum.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. In order to compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event.

In addition to logging where events occur within the network, the traffic log events must also identify sources of events, such as IP addresses, processes, and node or device names.'
  desc 'check', "Examine the traffic log configuration on the firewall or view several alert events on the organization's central audit server.

Verify the entries sent to the traffic log include sufficient information to ascertain the source of the events (e.g., IP address, session, or packet ID).

If the traffic log entries do not include sufficient information to ascertain the source of the events, this is a finding."
  desc 'fix', 'Configure the firewall implementation to ensure entries sent to the traffic log include sufficient information to ascertain the source of each event (e.g., IP address, session, or packet ID).'
  impact 0.3
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6938r297822_chk'
  tag severity: 'low'
  tag gid: 'V-206681'
  tag rid: 'SV-206681r604133_rule'
  tag stig_id: 'SRG-NET-000077-FW-000012'
  tag gtitle: 'SRG-NET-000077'
  tag fix_id: 'F-6938r297823_fix'
  tag 'documentable'
  tag legacy: ['SV-94147', 'V-79441']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
