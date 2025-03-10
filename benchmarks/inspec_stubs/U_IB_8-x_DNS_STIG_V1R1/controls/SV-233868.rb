control 'SV-233868' do
  title 'For zones split between the external and internal sides of a network, the resource records (RRs) for the external hosts must be separate from the RRs for the internal hosts.'
  desc 'Authoritative name servers for an enterprise may be configured to receive requests from both external and internal clients. 

External clients need to receive RRs that pertain only to public services (public web server, mail server, etc.) 

Internal clients need to receive RRs pertaining to public services as well as internal hosts. 

Organizations using dedicated internal systems and separate dedicated external systems are inherently more secure than using a single system accessed by both internal and external clients.

DNS Views allow a single name server to provide different response data based on a client match list or Access Control List.'
  desc 'check', 'DNS Views allow a single zone to have two different data sets, with the response based on a client match list.  

1. When DNS Views are used, the top-level configuration of DNS >> Data Management >> Zones tab will display available views.  
2. Select the desired view using the check box and click "Edit".  
3. Review the "Match Clients" configuration.
4. Verify the "Match Clients" configuration properly separates the internal and external DNS views.
 
If DNS Views are used and the client match list is validated, this is not a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Zones and review each zone. 
2. Remove any RRs listed in the internal name server configuration (DNS view) that resolve for external hosts.
3. Remove any RRs listed in the external name server configuration (DNS view) that resolve to internal hosts.
4. For hosts intended to be accessed by both internal and external clients, configure unique IP addresses in each of the internal and external name servers, respective to their location.  
5. The perimeter firewall, or other routing device, must be configured to perform Network Address Translation to the true IP address of the destination.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37053r611124_chk'
  tag severity: 'medium'
  tag gid: 'V-233868'
  tag rid: 'SV-233868r621666_rule'
  tag stig_id: 'IDNS-8X-400010'
  tag gtitle: 'SRG-APP-000516-DNS-000091'
  tag fix_id: 'F-37018r611125_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
