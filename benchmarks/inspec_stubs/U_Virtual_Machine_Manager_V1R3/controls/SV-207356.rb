control 'SV-207356' do
  title 'The VMM must produce audit records containing information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the VMM after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Verify the VMM produces audit records containing information to establish the outcome of the events. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to produce audit records containing information to establish the outcome of the events.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7613r365478_chk'
  tag severity: 'medium'
  tag gid: 'V-207356'
  tag rid: 'SV-207356r378628_rule'
  tag stig_id: 'SRG-OS-000041-VMM-000190'
  tag gtitle: 'SRG-OS-000041'
  tag fix_id: 'F-7613r365479_fix'
  tag 'documentable'
  tag legacy: ['SV-71149', 'V-56889']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
