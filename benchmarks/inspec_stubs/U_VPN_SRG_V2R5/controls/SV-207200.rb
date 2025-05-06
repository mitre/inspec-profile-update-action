control 'SV-207200' do
  title 'The VPN Gateway must produce log records containing information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the network.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the network after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', "Examine the log configuration on the VPN Gateway or view several alert events on the organization's central audit server. Alternatively, examine the Central Log Server to see if it contains information about success or failure of client connection attempts or other events.

If the traffic log entries do not include the success or failure of connection attempts and other events, this is a finding."
  desc 'fix', 'Configure the VPN Gateway to generate log entries containing information to establish the outcome of the events, such as, at a minimum, the success or failure of the client connection attempts.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7460r378221_chk'
  tag severity: 'medium'
  tag gid: 'V-207200'
  tag rid: 'SV-207200r608988_rule'
  tag stig_id: 'SRG-NET-000091-VPN-000350'
  tag gtitle: 'SRG-NET-000091'
  tag fix_id: 'F-7460r378222_fix'
  tag 'documentable'
  tag legacy: ['SV-106209', 'V-97071']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
