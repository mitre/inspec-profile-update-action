control 'SV-214160' do
  title 'Primary authoritative name servers must be configured to only receive zone transfer requests from specified secondary name servers.'
  desc 'Authoritative name servers (especially primary name servers) should be configured with an allow-transfer access control substatement designating the list of hosts from which zone transfer requests can be accepted. These restrictions address the denial-of-service threat and potential exploits from unrestricted dissemination of information about internal resources. Based on the need-to-know, the only name servers that need to refresh their zone files periodically are the secondary name servers. Zone transfer from primary name servers should be restricted to secondary name servers. The zone transfer should be completely disabled in the secondary name servers. The address match list argument for the allow-transfer substatement should consist of IP addresses of secondary name servers and stealth secondary name servers.'
  desc 'check', 'Infoblox grid members do not utilize DNS zone transfers to exchange DNS data. Communication between grid members is via a distributed database over a secure Virtual Private Network (VPN).

If configured to utilize zone transfers to external DNS servers, ensure Access Control Lists are configured to restrict data flow.

If Access Controls Lists are not configured for zone transfers to external non-Grid servers, this is a finding.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Members/Servers tab and configure access control (ACL or ACE) on each grid member which communicates with an external secondary.

When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15375r295746_chk'
  tag severity: 'medium'
  tag gid: 'V-214160'
  tag rid: 'SV-214160r612370_rule'
  tag stig_id: 'IDNS-7X-000020'
  tag gtitle: 'SRG-APP-000516-DNS-000095'
  tag fix_id: 'F-15373r295747_fix'
  tag 'documentable'
  tag legacy: ['V-68517', 'SV-83007']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
