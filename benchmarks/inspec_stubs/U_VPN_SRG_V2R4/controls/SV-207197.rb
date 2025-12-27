control 'SV-207197' do
  title 'The VPN Gateway must generate log records containing information that establishes the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.'
  desc 'check', 'Verify the VPN Gateway generates log records containing information that establishes the identity of any individual or process associated with the event.

If the VPN Gateway does not generate log records containing information that establishes the identity of any individual or process associated with the event, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to generate log records containing information that establishes the identity of any individual or process associated with the event.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7457r378212_chk'
  tag severity: 'medium'
  tag gid: 'V-207197'
  tag rid: 'SV-207197r608988_rule'
  tag stig_id: 'SRG-NET-000079-VPN-000300'
  tag gtitle: 'SRG-NET-000079'
  tag fix_id: 'F-7457r378213_fix'
  tag 'documentable'
  tag legacy: ['SV-106203', 'V-97065']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
