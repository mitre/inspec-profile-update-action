control 'SV-239972' do
  title 'The Cisco ASA remote access VPN server must be configured to generate log records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know where events occurred, such as VPN gateway components, modules, device identifiers, node names, and functionality.

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured VPN gateway.'
  desc 'check', 'Review the ASA configuration to determine if VPN events are logged as shown in the example below.

logging class vpn trap notifications 
logging class vpnc trap notifications 
logging class vpnfo trap notifications 
logging class webfo trap notifications 
logging class webvpn trap notifications 
logging class svc trap notifications

Note: A logging list can be used as an alternative to using class.

If the ASA does not generate log records containing information to establish where the events occurred, this is a finding.'
  desc 'fix', 'Configure the ASA to generate log records containing information to establish where the events occurred as shown in the example below.

ciscoasa(config)# logging class vpn trap notifications 
ciscoasa(config)# logging class vpnc trap notifications 
ciscoasa(config)# logging class vpnfo trap notifications 
ciscoasa(config)# logging class webvpn trap notifications 
ciscoasa(config)# logging class webfo trap notifications
ciscoasa(config)# logging class svc trap notifications 
ciscoasa(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43205r666320_chk'
  tag severity: 'medium'
  tag gid: 'V-239972'
  tag rid: 'SV-239972r666322_rule'
  tag stig_id: 'CASA-VN-000510'
  tag gtitle: 'SRG-NET-000088-VPN-000310'
  tag fix_id: 'F-43164r666321_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
