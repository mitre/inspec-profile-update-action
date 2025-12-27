control 'SV-233859' do
  title 'All authoritative name servers for a zone must be geographically disbursed.'
  desc %q(In addition to network-based dispersion, authoritative name servers should be dispersed geographically as well. In other words, in addition to being located on different network segments, the authoritative name servers should not all be located within the same building. One approach that some organizations follow is to locate some authoritative name servers in their own premises and others in their ISPs' data centers or in partnering organizations.

A network administrator may choose to use a "hidden" master authoritative server and have only secondary servers visible on the network. A hidden master authoritative server is an authoritative DNS server in which the IP address does not appear in the name server set for a zone.  If the master authoritative name server is "hidden", a secondary authoritative name server may reside in the same building as the hidden master.)
  desc 'check', '1. Navigate to Data Management >> DNS >> Zones tab. 
2. Review each zone by clicking "Edit" and inspecting the "Name Servers" tab.  
3. Review the name server (NS) records for each zone hosted and confirm that each authoritative name server is located at a different physical location than the remaining name servers. 
4. Infoblox supports designation as a "stealth" name server, which will not have an NS record.  

If all name servers for which NS records are published within a zone are not physically at different locations, this is a finding.'
  desc 'fix', 'Configure the authoritative name servers to be geographically disbursed.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37044r611097_chk'
  tag severity: 'medium'
  tag gid: 'V-233859'
  tag rid: 'SV-233859r621666_rule'
  tag stig_id: 'IDNS-8X-400001'
  tag gtitle: 'SRG-APP-000218-DNS-000027'
  tag fix_id: 'F-37009r611098_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
