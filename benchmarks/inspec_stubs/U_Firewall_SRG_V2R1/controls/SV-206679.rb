control 'SV-206679' do
  title 'The firewall must generate traffic log entries containing information to establish when (date and time) the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment, and provide forensic analysis of network traffic patterns, it is essential for security personnel to know when flow control events occurred (date and time) within the infrastructure.

Associating event types with detected events in the network traffic logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.'
  desc 'check', "Examine the traffic log configuration on the firewall or view several alert events on the organization's central audit server.

Verify the entries sent to the traffic log include the date and time of each event.

If the traffic log entries do not include the date and time the event occurred, this is a finding."
  desc 'fix', 'Configure the firewall to ensure entries sent to the traffic log include the date and time of the event.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6936r297816_chk'
  tag severity: 'medium'
  tag gid: 'V-206679'
  tag rid: 'SV-206679r604133_rule'
  tag stig_id: 'SRG-NET-000075-FW-000010'
  tag gtitle: 'SRG-NET-000075'
  tag fix_id: 'F-6936r297817_fix'
  tag 'documentable'
  tag legacy: ['SV-94143', 'V-79437']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
