control 'SV-205202' do
  title 'The DNS server implementation must require devices to re-authenticate for each zone transfer and dynamic update request connection attempt.'
  desc 'Without re-authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

In addition to the re-authentication requirements associated with session locks, organizations may require re-authentication of devices, including, but not limited to, the following other situations:
(i) When authenticators change;
(ii) When roles change;
(iii) When security categories of information systems change;
(iv) After a fixed period of time; or
(v) Periodically.

DNS does perform server authentication when DNSSEC or TSIG/SIG(0) are used, but this authentication is transactional in nature (each transaction has its own authentication performed). So this requirement is applicable for every server-to-server transaction request.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server requires devices to re-authenticate each time a zone transfer is initiated and each time a client makes a dynamic update request. If the DNS server does not require devices to re-authenticate each time a zone transfer is initiated and each time a client makes a dynamic update request, this is a finding. Note that the requirement should be inherently met if DNSSEC and TSIG/SIG(0) are enabled.'
  desc 'fix', 'Configure the DNS server to require devices to re-authenticate each time a zone transfer is initiated and each time a client makes a dynamic update request. Note that the requirement should be inherently met if DNSSEC and TSIG/SIG(0) are enabled.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5469r392519_chk'
  tag severity: 'medium'
  tag gid: 'V-205202'
  tag rid: 'SV-205202r879763_rule'
  tag stig_id: 'SRG-APP-000390-DNS-000048'
  tag gtitle: 'SRG-APP-000390'
  tag fix_id: 'F-5469r392520_fix'
  tag 'documentable'
  tag legacy: ['SV-69103', 'V-54857']
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
