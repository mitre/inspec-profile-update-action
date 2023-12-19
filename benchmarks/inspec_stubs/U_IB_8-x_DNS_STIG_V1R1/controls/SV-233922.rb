control 'SV-233922' do
  title 'The Infoblox system must manage excess capacity, bandwidth, or other redundancy to limit the effects of information-flooding types of denial-of-service (DoS) attacks.'
  desc 'A DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

In the case of application DoS attacks, care must be taken when designing the application to ensure the application makes the best use of system resources. SQL queries have the potential to consume large amounts of CPU cycles if they are not tuned for optimal performance. Web services containing complex calculations requiring large amounts of time to complete can bog down if too many requests for the service are encountered within a short period of time. 

A DoS attack against the DNS infrastructure has the potential to cause a DoS to all network users. As the DNS is a distributed backbone service of the internet, various forms of amplification attacks resulting in DoS, while using the DNS, are still prevalent on the internet today. Some potential DoS flooding attacks against the DNS include malformed packet flood, spoofed source addresses, and distributed DoS. Without the DNS, users and systems would not have the ability to perform simple name-to-IP resolution. 

Configuring the DNS implementation to defend against cache poisoning, employing increased capacity and bandwidth, building redundancy into the DNS architecture, using DNSSEC, and limiting and securing recursive services, DNS black holes, etc., may reduce the susceptibility to some flooding types of DoS attacks.'
  desc 'check', 'Infoblox systems have a number of options that can be configured to reduce the ability to be exploited in a DoS attack. Use of rate limiting can reduce risk from cache poisoning attacks and DoS attacks. 

1. Log on to the Infoblox system CLI and issue the following commands:
"show ip_rate_limit" and "show dns_rrl" 
2. Review the output from these commands with the network architecture.  
3. If the system uses the Advanced DNS Protection (ADP) (Threat Protection) feature, IP rate limiting is implemented using the DNS security rule-set available in the web GUI. 

If the ADP feature set is implemented, use of the ip_rate_limit and dns_rrl CLI commands is not required, and this check is Not Applicable. Refer to the Infoblox Admin Guide for additional details if needed.  

If rate limiting is not configured on the Infoblox system or within the network security architecture protecting the Infoblox system, this is a finding.'
  desc 'fix', 'Prior to implementation, review the Infoblox CLI Guide and verify all configuration options.
 
1. Log on to the Infoblox system using the CLI.   
2. Use "set ip_rate_limit [OPTIONS}" to reduce risk of cache poisoning attacks by rate limiting udp/53 traffic.  
3. Use "set dns_rrl [OPTIONS]" to enable DNS response rate limiting. 
4. Upon completion, log out of the CLI.  

This helps reduce the risk of DoS attacks by reducing the rate at which authoritative name servers respond to queries, such as a flood.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37107r611286_chk'
  tag severity: 'medium'
  tag gid: 'V-233922'
  tag rid: 'SV-233922r621666_rule'
  tag stig_id: 'IDNS-8X-700017'
  tag gtitle: 'SRG-APP-000247-DNS-000036'
  tag fix_id: 'F-37072r611287_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
