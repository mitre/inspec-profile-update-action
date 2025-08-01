control 'SV-229030' do
  title 'The Cisco router must be configured to have Cisco Express Forwarding enabled.'
  desc 'The Cisco Express Forwarding (CEF) switching mode replaces the traditional Cisco routing cache with a data structure that mirrors the entire system routing table. Because there is no need to build cache entries when traffic starts arriving for new destinations, CEF behaves more predictably when presented with large volumes of traffic addressed to many destinations—such as a SYN flood attacks that. Because many SYN flood attacks use randomized source addresses to which the hosts under attack will reply to, there can be a substantial amount of traffic for a large number of destinations that the router will have to handle. Consequently, routers configured for CEF will perform better under SYN floods directed at hosts inside the network than routers using the traditional cache.'
  desc 'check', 'Review the router to verify that CEF is enabled.

IPv4 Example: ip cef 
IPv6 Example: ipv6 cef'
  desc 'fix', 'Enable CEF

IPv4 Example: ip cef 
IPv6 Example: ipv6 cef'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-31345r802613_chk'
  tag severity: 'medium'
  tag gid: 'V-229030'
  tag rid: 'SV-229030r531380_rule'
  tag stig_id: 'CISC-RT-000235'
  tag gtitle: 'SRG-NET-000512-RTR-000100'
  tag fix_id: 'F-31322r802614_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
