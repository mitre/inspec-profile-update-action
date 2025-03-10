control 'SV-68665' do
  title 'The ALG must produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment, and provide forensic analysis of network traffic patterns, it is essential for security personnel to know when flow control events occurred within the infrastructure.

Associating event types with detected events in the network audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ALG produces audit records containing information to establish when (date and time) the events occurred.

If the ALG does not produce audit records containing information to establish when (date and time) the events occurred, this is a finding.'
  desc 'fix', 'Configure the ALG to produce audit records containing information to establish when (date and time) the events occurred.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55035r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54419'
  tag rid: 'SV-68665r1_rule'
  tag stig_id: 'SRG-NET-000075-ALG-000044'
  tag gtitle: 'SRG-NET-000075-ALG-000044'
  tag fix_id: 'F-59273r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
