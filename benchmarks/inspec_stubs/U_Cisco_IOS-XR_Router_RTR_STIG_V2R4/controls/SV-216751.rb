control 'SV-216751' do
  title 'The Cisco router must be configured to produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event.

In addition to logging where events occur within the network, the audit records must also identify sources of events such as IP addresses, processes, and node or device names.'
  desc 'check', 'Review the router configuration to verify that events are logged containing information to establish the source of the events as shown in the example below.

ipv4 access-list EXTERNAL_ACL_INBOUND
 10 permit tcp host x.11.1.1 eq bgp host x.11.1.2
 20 permit tcp host x.11.1.1 host x.11.1.2 eq bgp
 25 deny icmp any host x.11.1.2 fragments log 
 30 permit icmp host x.11.1.1 host x.11.1.2 echo
 40 permit icmp host x.11.1.1 host x.11.1.2 echo-reply
 50 deny ipv4 any host x.11.1.1 log-input
 60 permit tcp any any established
 …
 …
 …
 140 deny ipv4 any any log-input

Note: When the log-input parameter is configured on deny statements, the log record will contain the layer 2 address of the forwarding device for any packet being dropped.

If the router is not configured to produce audit records containing information to establish the source of the events, this is a finding.'
  desc 'fix', 'Configure the router to log events containing information to establish where the events occurred as shown in the example below.
 
RP/0/0/CPU0:R3(config)#ipv4 access-list EXTERNAL_ACL_INBOUND
…
…
…
RP/0/0/CPU0:R3(config-ipv4-acl)#deny ip any any log-input'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17983r288642_chk'
  tag severity: 'medium'
  tag gid: 'V-216751'
  tag rid: 'SV-216751r531087_rule'
  tag stig_id: 'CISC-RT-000220'
  tag gtitle: 'SRG-NET-000077-RTR-000001'
  tag fix_id: 'F-17981r288643_fix'
  tag 'documentable'
  tag legacy: ['SV-105847', 'V-96709']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
