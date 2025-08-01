control 'SV-85959' do
  title 'The CA API Gateway must generate audit records containing information to establish the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.

The CA API Gateway must have the "Audit Messages in Policy" Assertion added to all policies.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and verify all of the Registered Services have the "Audit Messages in Policy" Assertion added to the Service. 

If any of the Registered Services do not have the "Audit Messages in Policy" Assertion added, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager.

Open the Registered Services that do not have the "Audit Messages in Policy" Assertion and add it to the top of the Registered Services policies.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71735r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71335'
  tag rid: 'SV-85959r1_rule'
  tag stig_id: 'CAGW-GW-000230'
  tag gtitle: 'SRG-NET-000079-ALG-000048'
  tag fix_id: 'F-77645r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
