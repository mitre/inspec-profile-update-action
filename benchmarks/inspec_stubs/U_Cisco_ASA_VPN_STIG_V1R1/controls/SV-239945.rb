control 'SV-239945' do
  title 'The Cisco ASA must be configured to generate log records containing information to establish what type of VPN events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

VPN gateways often have a separate audit log for capturing VPN status and other information about the traffic (as opposed to the log capturing administrative and configuration actions). Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the VPN gateway logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured VPN gateway.'
  desc 'check', 'Review the ASA configuration to determine if VPN events are logged as shown in the example below.

logging class vpn trap notifications 
logging class vpnc trap notifications 
logging class vpnfo trap notifications 
logging class webfo trap notifications 
logging class webvpn trap notifications 
logging class svc trap notifications

Note: A logging list can be used as an alternative to using class.

If the ASA is not configured to log entries containing information to establish what type of VPN events occurred, this is a finding.'
  desc 'fix', 'Configure the ASA to generate logs containing information to establish what type of VPN events occurred as shown in the example below.

ciscoasa(config)# logging class vpn trap notifications 
ciscoasa(config)# logging class vpnc trap notifications 
ciscoasa(config)# logging class vpnfo trap notifications 
ciscoasa(config)# logging class webvpn trap notifications 
ciscoasa(config)# logging class webfo trap notifications
ciscoasa(config)# logging class svc trap notifications 
ciscoasa(config)# end'
  impact 0.3
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43178r666239_chk'
  tag severity: 'low'
  tag gid: 'V-239945'
  tag rid: 'SV-239945r666241_rule'
  tag stig_id: 'CASA-VN-000010'
  tag gtitle: 'SRG-NET-000077-VPN-000280'
  tag fix_id: 'F-43137r666240_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
