control 'SV-69087' do
  title 'The DNS server implementation must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  desc 'A DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

In the case of application DoS attacks, care must be taken when designing the application to ensure the application makes the best use of system resources. SQL queries have the potential to consume large amounts of CPU cycles if they are not tuned for optimal performance. Web services containing complex calculations requiring large amounts of time to complete can bog down if too many requests for the service are encountered within a short period of time. 

A denial of service (DoS) attack against the DNS infrastructure has the potential to cause a DoS to all network users. As the DNS is a distributed backbone service of the Internet, various forms of amplification attacks resulting in DoS, while utilizing the DNS, are still prevalent on the Internet today. Some potential DoS flooding attacks against the DNS include malformed packet flood, spoofed source addresses, and distributed DoS. Without the DNS, users and systems would not have the ability to perform simple name to IP resolution. 

Configuring the DNS implementation to defend against cache poisoning, employing increased capacity and bandwidth, building redundancy into the DNS architecture, utilizing DNSSEC, limiting and securing recursive services, DNS black holes, etc., may reduce the susceptibility to some flooding types of DoS attacks.'
  desc 'check', 'Review the DNS server implementation and configuration to determine if excess capacity and bandwidth are managed and redundancy is built into the system to limit the effects of information flooding types of DoS attacks. 

If excess capacity and bandwidth are not managed, or redundancy is not built into the architecture, this is a finding.'
  desc 'fix', 'Configure the DNS server to manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of DoS attacks.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55463r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54841'
  tag rid: 'SV-69087r1_rule'
  tag stig_id: 'SRG-APP-000247-DNS-000036'
  tag gtitle: 'SRG-APP-000247-DNS-000036'
  tag fix_id: 'F-59699r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
