control 'SV-239855' do
  title 'The Cisco ASA must be configured to generate traffic log entries containing information to establish what type of events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit event content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the network element logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.'
  desc 'check', 'Review the ASA configuration to determine if it is compliant with the requirement.

Step 1: Verify that all ACL deny statements have the log parameter defined as shown in the example below.

access-list OUTSIDE_OUT extended deny ip any any log

Step 2: Verify logging is enabled.

logging enable

If the ASA is not configured to generate traffic log entries containing information to establish what type of events occurred, this is a finding.'
  desc 'fix', 'Configure the ASA to generate traffic log entries containing information to establish what type of events occurred as shown in the example below.

Step 1: Enable logging.

ASA(config)# logging enable

Step 2: Include the log parameter on all deny ACL statements.

ASA(config)# access-list OUTSIDE_OUT extended deny ip any any log'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43088r665849_chk'
  tag severity: 'medium'
  tag gid: 'V-239855'
  tag rid: 'SV-239855r665851_rule'
  tag stig_id: 'CASA-FW-000040'
  tag gtitle: 'SRG-NET-000074-FW-000009'
  tag fix_id: 'F-43047r665850_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
