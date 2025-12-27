control 'SV-239974' do
  title 'The Cisco ASA remote access VPN server must be configured to produce log records containing information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the network.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the network after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Verify the ASA generates log records containing information to establish the outcome of the events as shown in the example below.

logging class vpn trap notifications 
logging class vpnc trap notifications 
logging class vpnfo trap notifications 
logging class webfo trap notifications 
logging class webvpn trap notifications 
logging class svc trap notifications

Note: A logging list can be used as an alternative to using class.

If the ASA does not generate log records containing information to establish the source of the events, this is a finding.'
  desc 'fix', 'Configure the ASA to generate log entries containing information to establish the outcome of the events as shown in the example below.

ciscoasa(config)# logging class vpn trap notifications 
ciscoasa(config)# logging class vpnc trap notifications 
ciscoasa(config)# logging class vpnfo trap notifications 
ciscoasa(config)# logging class webvpn trap notifications 
ciscoasa(config)# logging class webfo trap notifications
ciscoasa(config)# logging class svc trap notifications 
ciscoasa(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43207r666326_chk'
  tag severity: 'medium'
  tag gid: 'V-239974'
  tag rid: 'SV-239974r666328_rule'
  tag stig_id: 'CASA-VN-000530'
  tag gtitle: 'SRG-NET-000091-VPN-000350'
  tag fix_id: 'F-43166r666327_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
