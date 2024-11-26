control 'SV-221004' do
  title 'The Cisco switch must be configured to produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as switch components, modules, device identifiers, node names, and functionality.

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured switch.'
  desc 'check', 'Review the switch configuration to verify that events are logged containing information to establish where the events occurred as shown in the example below:

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
deny ip any any log-input

Note: When the log-input parameter is configured on deny statements, the log record will contain the interface where ingress packet has been dropped.

If the switch is not configured to produce audit records containing information to establish to establish where the events occurred, this is a finding.'
  desc 'fix', 'Configure the switch to log events containing information to establish where the events occurred as shown in the example below:

SW1(config)#ip access-list extended INGRESS_FILTER
…
…
…
SW1(config-ext-nacl)#deny ip any any log-input'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22719r408806_chk'
  tag severity: 'medium'
  tag gid: 'V-221004'
  tag rid: 'SV-221004r622190_rule'
  tag stig_id: 'CISC-RT-000210'
  tag gtitle: 'SRG-NET-000076-RTR-000001'
  tag fix_id: 'F-22708r408807_fix'
  tag 'documentable'
  tag legacy: ['SV-110829', 'V-101725']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
