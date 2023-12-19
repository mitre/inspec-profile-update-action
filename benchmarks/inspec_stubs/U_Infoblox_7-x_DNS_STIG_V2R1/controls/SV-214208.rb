control 'SV-214208' do
  title 'For zones split between the external and internal sides of a network, the RRs for the external hosts must be separate from the RRs for the internal hosts.'
  desc 'Authoritative name servers for an enterprise may be configured to receive requests from both external and internal clients. 

External clients need to receive RRs that pertain only to public services (public Web server, mail server, etc.) 

Internal clients need to receive RRs pertaining to public services as well as internal hosts. 

The zone information that serves the RRs on both the inside and the outside of a firewall should be split into different physical files for these two types of clients (one file for external clients and one file for internal clients).'
  desc 'check', 'There are two primary configuration options for this requirement.

1. DNS Views allow a single zone to have two different data sets, with the response based on a client match list.

If DNS Views are used and the client match list is validated, this is not a finding.

2. Review the Resource Records (RRs) of each zone which is split between external and internal networks. For those internal hosts which are intended to be accessed by both internal and external users, a different RR should be listed on each of the internal and external name servers, with IP addresses reflective of the external or internal network. Traffic destined for those internal hosts will resolve to the IP address in the external name server and then should be NATd through the perimeter firewall.

If a different Resource Record (RR) is not listed on each of the internal and external name servers, this is a finding.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Zones and review each zone.

Remove any RRs listed in the internal name server configuration (or DNS view) which resolve for external hosts and remove any RRs listed in the external name server configuration which resolve to internal hosts.

For hosts intended to be accessed by both internal and external clients, configure unique IP addresses in each of the internal and external name servers, respective to their location. The perimeter firewall, or other routing device, should handle the Network Address Translation to the true IP address of the destination.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15423r295887_chk'
  tag severity: 'medium'
  tag gid: 'V-214208'
  tag rid: 'SV-214208r612370_rule'
  tag stig_id: 'IDNS-7X-000790'
  tag gtitle: 'SRG-APP-000516-DNS-000091'
  tag fix_id: 'F-15421r295888_fix'
  tag 'documentable'
  tag legacy: ['SV-83101', 'V-68611']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
