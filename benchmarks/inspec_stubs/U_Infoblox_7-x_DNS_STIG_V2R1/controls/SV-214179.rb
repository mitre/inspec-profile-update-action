control 'SV-214179' do
  title 'The Infoblox system must be configured to manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  desc 'A DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

In the case of application DoS attacks, care must be taken when designing the application to ensure the application makes the best use of system resources. SQL queries have the potential to consume large amounts of CPU cycles if they are not tuned for optimal performance. Web services containing complex calculations requiring large amounts of time to complete can bog down if too many requests for the service are encountered within a short period of time. 

A denial of service (DoS) attack against the DNS infrastructure has the potential to cause a DoS to all network users. As the DNS is a distributed backbone service of the Internet, various forms of amplification attacks resulting in DoS, while utilizing the DNS, are still prevalent on the Internet today. Some potential DoS flooding attacks against the DNS include malformed packet flood, spoofed source addresses, and distributed DoS. Without the DNS, users and systems would not have the ability to perform simple name to IP resolution. 

Configuring the DNS implementation to defend against cache poisoning, employing increased capacity and bandwidth, building redundancy into the DNS architecture, utilizing DNSSEC, limiting and securing recursive services, DNS black holes, etc., may reduce the susceptibility to some flooding types of DoS attacks.'
  desc 'check', 'Infoblox systems have a number of options that can be configured to reduce the ability to be exploited in a DoS attack. Usage of rate limiting can reduce risk from cache poisoning attacks and DoS attacks.

Log on to the Infoblox system and issue the commands:

"show ip_rate_limit" and "show dns_rrl"

Review the output from these commands with the network architecture.

If rate limiting is not configured on the Infoblox system or within the network security architecture, this is a finding.

Note: "set dns_rrl" is only applicable to code version 7.2 and above.'
  desc 'fix', 'Log on to the Infoblox system using the CLI.

Use "set ip_rate_limit [OPTIONS}" to reduce risk of cache poisoning attacks by rate limiting udp/53 traffic.

Use "set dns_rrl" to enable DNS response rate limiting. This helps reduce the risk of DoS attacks by reducing the rate at which authoritative name servers respond to queries, such as a flood.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15394r295800_chk'
  tag severity: 'medium'
  tag gid: 'V-214179'
  tag rid: 'SV-214179r612370_rule'
  tag stig_id: 'IDNS-7X-000350'
  tag gtitle: 'SRG-APP-000247-DNS-000036'
  tag fix_id: 'F-15392r295801_fix'
  tag 'documentable'
  tag legacy: ['V-68553', 'SV-83043']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
