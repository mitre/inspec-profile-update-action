control 'SV-203608' do
  title 'The operating system must produce audit records containing information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Verify the operating system produces audit records containing information to establish the outcome of the events. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to produce audit records containing information to establish the outcome of the events.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3733r557080_chk'
  tag severity: 'medium'
  tag gid: 'V-203608'
  tag rid: 'SV-203608r557082_rule'
  tag stig_id: 'SRG-OS-000041-GPOS-00019'
  tag gtitle: 'SRG-OS-000041'
  tag fix_id: 'F-3733r557081_fix'
  tag 'documentable'
  tag legacy: ['V-56655', 'SV-70915']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
