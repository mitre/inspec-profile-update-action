control 'SV-74353' do
  title 'The BIG-IP AFM module must be configured to produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the gateway logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', "Verify the BIG-IP AFM module is configured to produce audit records containing information to establish what type of events occurred.

Navigate to the BIG-IP System manager >> Security >> Event Logs >> Logging Profiles.

Verify list of Profiles 'Enabled' for 'Network Firewall'.

If the BIG-IP AFM module does not produce audit records containing information to establish what type of events occurred, this is a finding."
  desc 'fix', "Configure the BIG-IP AFM module to produce audit records containing information to establish what type of events occurred. 

Navigate to the BIG-IP System manager >> Security >> Event Logs >> Logging Profiles.

Click on 'Create'.

Name the Profile.

Check the box next to 'Network Firewall'.

Configure settings to log required information.

Click 'Finished'."
  impact 0.5
  ref 'DPMS Target F5 BIG-IP AFM 11.x'
  tag check_id: 'C-60613r1_chk'
  tag severity: 'medium'
  tag gid: 'V-59923'
  tag rid: 'SV-74353r1_rule'
  tag stig_id: 'F5BI-AF-000039'
  tag gtitle: 'SRG-NET-000074-ALG-000043'
  tag fix_id: 'F-65333r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
