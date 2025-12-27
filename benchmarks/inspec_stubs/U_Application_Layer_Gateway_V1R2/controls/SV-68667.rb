control 'SV-68667' do
  title 'The ALG must produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know where events occurred, such as network element components, modules, device identifiers, node names, and functionality.

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ALG produces audit records containing information to establish where the events occurred.

If the ALG does not produce audit records containing information to establish where the events occurred, this is a finding.'
  desc 'fix', 'Configure the ALG to produce audit records containing information to establish where the events occurred.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55037r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54421'
  tag rid: 'SV-68667r1_rule'
  tag stig_id: 'SRG-NET-000076-ALG-000045'
  tag gtitle: 'SRG-NET-000076-ALG-000045'
  tag fix_id: 'F-59275r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
