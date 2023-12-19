control 'SV-206678' do
  title 'The firewall must generate traffic log entries containing information to establish what type of events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit event content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the network element logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.'
  desc 'check', "Examine the traffic log configuration on the firewall or view several alert events on the organization's central audit server.

Verify the entries sent to the traffic log include sufficient information to determine the type or category for each event in the traffic log.

If the traffic log entries do not include enough information to determine what type of event occurred, this is a finding."
  desc 'fix', 'Configure the firewall to ensure entries sent to the traffic log include sufficient information to determine the type or category for each event in the traffic log.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6935r297813_chk'
  tag severity: 'medium'
  tag gid: 'V-206678'
  tag rid: 'SV-206678r604133_rule'
  tag stig_id: 'SRG-NET-000074-FW-000009'
  tag gtitle: 'SRG-NET-000074'
  tag fix_id: 'F-6935r297814_fix'
  tag 'documentable'
  tag legacy: ['SV-94141', 'V-79435']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
