control 'SV-237036' do
  title 'The A10 Networks ADC must use DNS Proxy mode when Global Server Load Balancing is used.'
  desc 'Unrelated or unneeded proxy services increase the attack vector and add excessive complexity to the securing of the device. Multiple application proxies can be installed on many devices. However, proxy types must be limited to related functions.

The A10 Networks ADC is capable of DNS-based Global Server Load Balancing (GSLB), which uses Domain Name Service (DNS) to expand load balancing to larger scales, including globally. Global Server Load Balancing can operate in either Proxy mode or Server mode. In Proxy mode, all DNS queries arriving at the DNS Proxy IP address are forwarded to the existing DNS server. In Server mode, the device directly responds to queries for specific service IP addresses in the GSLB zone and can reply with A, AAAA, MX, NS, PTR, SRV, and SOA records. For all other records, the ACOS device will attempt Proxy mode unless configured as fully authoritative.'
  desc 'check', 'If DNS-based Global Server Load Balancing is not configured, this is not applicable.

If DNS-based Global Server Load Balancing is configured, review the configuration. 

Check if real servers are configured for DNS. If they are not, then the device is in Server mode, and this is a finding.'
  desc 'fix', 'If GSLB is used, configure it for Proxy Mode. The difference is that Proxy mode has real servers configured, while Server mode does not.

To configure Proxy mode, follow standard SLB configuration steps (Servers, Service Groups, VIP, etc.) that utilize “external” DNS servers and enable it for GSLB when configuring the virtual port.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40255r639553_chk'
  tag severity: 'medium'
  tag gid: 'V-237036'
  tag rid: 'SV-237036r639555_rule'
  tag stig_id: 'AADC-AG-000035'
  tag gtitle: 'SRG-NET-000131-ALG-000086'
  tag fix_id: 'F-40218r639554_fix'
  tag 'documentable'
  tag legacy: ['SV-82455', 'V-67965']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
