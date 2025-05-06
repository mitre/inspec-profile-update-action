control 'SV-216570' do
  title 'The Cisco router must be configured to produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event.

In addition to logging where events occur within the network, the audit records must also identify sources of events such as IP addresses, processes, and node or device names.'
  desc 'check', 'Review the router configuration to verify that events are logged containing information to establish the source of the events as shown in the example below.

ip access-list extended INGRESS_FILTER
 permit tcp any any established
 permit tcp host x.11.1.1 eq bgp host x.11.1.2
 permit tcp host x.11.1.1 host x.11.1.2 eq bgp
 permit tcp any host x.11.1.5 eq www
 permit icmp host x.11.1.1 host x.11.1.2 echo
 permit icmp any any echo-reply
 …
 …
 …
deny   ip any any log-input

Note: When the log-input parameter is configured on deny statements, the log record will contain the layer 2 address of the forwarding device for any packet being dropped.

If the router is not configured to produce audit records containing information to establish the source of the events, this is a finding.'
  desc 'fix', 'Configure the router to log events containing information to establish where the events occurred as shown in the example below.
 
R5(config)#ip access-list extended INGRESS_FILTER
…
…
…
R5(config-ext-nacl)#deny ip any any log-input'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17805r287094_chk'
  tag severity: 'medium'
  tag gid: 'V-216570'
  tag rid: 'SV-216570r531085_rule'
  tag stig_id: 'CISC-RT-000220'
  tag gtitle: 'SRG-NET-000077-RTR-000001'
  tag fix_id: 'F-17801r287095_fix'
  tag 'documentable'
  tag legacy: ['SV-105679', 'V-96541']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
