control 'SV-239973' do
  title 'The Cisco ASA remote access VPN server must be configured to generate log records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. In order to compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event.

In addition to logging where events occur within the network, the log records must also identify sources of events such as IP addresses, processes, and node or device names.'
  desc 'check', 'Verify the ASA generates log records containing information to establish the source of the events as shown in the example below.

logging class vpn trap notifications 
logging class vpnc trap notifications 
logging class vpnfo trap notifications 
logging class webfo trap notifications 
logging class webvpn trap notifications 
logging class svc trap notifications

Note: A logging list can be used as an alternative to using class.

If the ASA does not generate log records containing information to establish the source of the events, this is a finding.'
  desc 'fix', 'Configure the ASA to generate log records containing information to establish the source of the events as shown in the example below.

ciscoasa(config)# logging class vpn trap notifications 
ciscoasa(config)# logging class vpnc trap notifications 
ciscoasa(config)# logging class vpnfo trap notifications 
ciscoasa(config)# logging class webvpn trap notifications 
ciscoasa(config)# logging class webfo trap notifications
ciscoasa(config)# logging class svc trap notifications 
ciscoasa(config)# end'
  impact 0.3
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43206r666323_chk'
  tag severity: 'low'
  tag gid: 'V-239973'
  tag rid: 'SV-239973r666325_rule'
  tag stig_id: 'CASA-VN-000520'
  tag gtitle: 'SRG-NET-000089-VPN-000330'
  tag fix_id: 'F-43165r666324_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
