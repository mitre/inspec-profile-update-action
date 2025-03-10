control 'SV-70915' do
  title 'The operating system must produce audit records containing information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Verify the operating system produces audit records containing information to establish the outcome of the events. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to produce audit records containing information to establish the outcome of the events.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57225r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56655'
  tag rid: 'SV-70915r1_rule'
  tag stig_id: 'SRG-OS-000041-GPOS-00019'
  tag gtitle: 'SRG-OS-000041-GPOS-00019'
  tag fix_id: 'F-61551r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
