control 'SV-220438' do
  title 'The Cisco switch must be configured to produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. 

To compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event. 

In addition to logging where events occur within the network, the audit records must also identify sources of events such as IP addresses, processes, and node or device names.'
  desc 'check', 'Review the switch configuration to verify that events are logged containing information to establish the source of the events as shown in the example below: 

ip access-list extended INGRESS_FILTER 
 permit tcp any any established 
 permit tcp any host x.11.1.5 eq www 
 permit icmp host x.11.1.1 host x.11.1.2 echo 
 permit icmp any any echo-reply 
… 
 … 
 … 
deny ip any any log-input 

Note: When the log-input parameter is configured on deny statements, the log record will contain the Layer 2 address of the forwarding device for any packet being dropped. 

If the switch is not configured to produce audit records containing information to establish the source of the events, this is a finding.'
  desc 'fix', 'Configure the switch to log events containing information to establish where the events occurred as shown in the example below: 

SW1(config)#ip access-list extended INGRESS_FILTER 
… 
… 
… 
SW1(config-ext-nacl)#deny ip any any log-input'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22153r508399_chk'
  tag severity: 'medium'
  tag gid: 'V-220438'
  tag rid: 'SV-220438r622190_rule'
  tag stig_id: 'CISC-RT-000220'
  tag gtitle: 'SRG-NET-000077-RTR-000001'
  tag fix_id: 'F-22142r508400_fix'
  tag 'documentable'
  tag legacy: ['SV-110723', 'V-101619']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
