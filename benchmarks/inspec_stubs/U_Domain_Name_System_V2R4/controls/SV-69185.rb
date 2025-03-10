control 'SV-69185' do
  title 'Primary authoritative name servers must be configured to only receive zone transfer requests from specified secondary name servers.'
  desc 'Authoritative name servers (especially primary name servers) should be configured with an allow-transfer access control substatement designating the list of hosts from which zone transfer requests can be accepted. These restrictions address the denial-of-service threat and potential exploits from unrestricted dissemination of information about internal resources. Based on the need-to-know, the only name servers that need to refresh their zone files periodically are the secondary name servers. Zone transfer from primary name servers should be restricted to secondary name servers. The zone transfer should be completely disabled in the secondary name servers. The address match list argument for the allow-transfer substatement should consist of IP addresses of secondary name servers and stealth secondary name servers.'
  desc 'check', 'Review the DNS configuration files. Verify a configuration is in place to limit the secondary name servers from which an authoritative name server receives zone transfer requests.

If a configuration is not in place to limit the secondary name servers from which an authoritative name server receives zone transfer requests, this is a finding.'
  desc 'fix', 'Configure the authoritative name server to specify which secondary name servers from which it will receive zone transfer requests.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55565r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54939'
  tag rid: 'SV-69185r1_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000095'
  tag gtitle: 'SRG-APP-000516-DNS-000095'
  tag fix_id: 'F-59801r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
