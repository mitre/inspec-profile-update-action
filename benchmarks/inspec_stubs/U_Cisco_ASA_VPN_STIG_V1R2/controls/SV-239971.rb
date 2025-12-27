control 'SV-239971' do
  title 'The Cisco ASA remote access VPN server must be configured to generate log records containing information that establishes the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.'
  desc 'check', 'Review the ASA configuration to determine if VPN events are logged as shown in the example below.

logging class vpn trap notifications 
logging class vpnc trap notifications 
logging class vpnfo trap notifications 
logging class webfo trap notifications 
logging class webvpn trap notifications 
logging class svc trap notifications

Note: A logging list can be used as an alternative to using class.

If the ASA is not configured to log entries containing information to establish the identity of any individual or process associated with the event, this is a finding.'
  desc 'fix', 'Configure the ASA to generate logs containing information to establish the identity of any individual or process associated with the event as shown in the example below.

ciscoasa(config)# logging class vpn trap notifications 
ciscoasa(config)# logging class vpnc trap notifications 
ciscoasa(config)# logging class vpnfo trap notifications 
ciscoasa(config)# logging class webvpn trap notifications 
ciscoasa(config)# logging class webfo trap notifications
ciscoasa(config)# logging class svc trap notifications 
ciscoasa(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43204r666317_chk'
  tag severity: 'medium'
  tag gid: 'V-239971'
  tag rid: 'SV-239971r666319_rule'
  tag stig_id: 'CASA-VN-000500'
  tag gtitle: 'SRG-NET-000079-VPN-000300'
  tag fix_id: 'F-43163r666318_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
