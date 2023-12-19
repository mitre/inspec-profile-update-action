control 'SV-251761' do
  title 'The NSX-T Tier-1 Gateway Firewall must generate traffic log entries containing information to establish what type of events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit event content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the network element logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.'
  desc 'check', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules. 

For each Tier-1 Gateway and for each rule, click the gear icon and verify the Logging setting.

If Logging is not "Enabled", this is a finding.'
  desc 'fix', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules. 

For each Tier-1 Gateway and for each rule with logging disabled, click the gear icon and enable Logging, then click "Apply".

After all changes are made, click "Publish".'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Tier 1 Gateway Firewall'
  tag check_id: 'C-55198r810176_chk'
  tag severity: 'medium'
  tag gid: 'V-251761'
  tag rid: 'SV-251761r810178_rule'
  tag stig_id: 'T1FW-3X-000005'
  tag gtitle: 'SRG-NET-000074-FW-000009'
  tag fix_id: 'F-55152r810177_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
