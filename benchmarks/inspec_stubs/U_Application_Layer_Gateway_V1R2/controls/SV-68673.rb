control 'SV-68673' do
  title 'The ALG must generate audit records containing information to establish the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ALG produces audit records containing information to establish the identity of any individual or process associated with the event.

If the ALG does not produce audit records containing information to establish the identity of any individual or process associated with the event, this is a finding.'
  desc 'fix', 'Configure the ALG to produce audit records containing information to establish the identity of any individual or process associated with the event.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55043r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54427'
  tag rid: 'SV-68673r1_rule'
  tag stig_id: 'SRG-NET-000079-ALG-000048'
  tag gtitle: 'SRG-NET-000079-ALG-000048'
  tag fix_id: 'F-59281r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
