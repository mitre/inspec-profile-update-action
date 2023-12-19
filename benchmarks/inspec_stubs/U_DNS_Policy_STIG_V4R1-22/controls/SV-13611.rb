control 'SV-13611' do
  title 'Name servers authoritative for a zone are not located on separate network segments if the host records described in the zone are themselves located across more than one network segment.'
  desc 'A critical component of securing an information system is ensuring its availability.  The best way to ensure availability is to eliminate any single point of failure in the system itself and in the network architecture that supports it.

Fortunately, the inherent design of DNS supports a high-availability environment.  Master and slave servers regularly communicate zone information, so if any name server is disabled at any time, another can immediately provide the same service.  The task for the network architect is to ensure that a disaster or outage cannot simultaneously impact both the master and all of its slave servers.  If a disaster occurs, the DNS protocols cannot prevent total loss of name resolution services for hosts within affected zones.

The solution is to disperse name servers in such a way as to avoid single points of failure.  At minimum, authoritative name servers for the same zone should be on different network segments in order that at least one name server is available in the event that a router or switch fails.  This fault tolerance should also extend to wide area data communications lines.  For example, if a site has multiple leased lines connecting the network on which the name server resides to a larger network such as the NIPRNet, routing protocols should be configured such that if one of the lines fails, another one will still be available to support the name server.'
  desc 'check', 'The intent of this requirement is to ensure all hosts in a zone can access an authoritative name server hosting their zone. Either a name server must reside on every subnet where hosts are located for each zone or name server on other subnets must be accessible for DNS queries by the hosts on subnets without a name server.

NOTE: For networks with only Active Directory authoritative zones, the Microsoft Windows 2012 Server Domain Name System Security Technical Implementation Guide should be followed for explicit guidance.

Determine if host records in a zone are on the same subnet. 

If the records are on one subnet primary and at least one secondary nameserver is required on that same subnet. 

If multiple subnets are found, then a server should be available for each subnet. Determine if there is a name server on each of the subnets where hosts are located. If name servers are not on each subnet where hosts are located, validate the installed name servers on other subnets are accessible by the hosts on the subnets without a name server.

If each subnet hosting hosts for a zone does not have a name server on the same subnet and name servers on other subnets are not accessible by the hosts on the subnet without a name server, this is a finding.

The reviewer can manually check the IP addresses of the servers being reviewed to determine if they are on the same subnet.'
  desc 'fix', 'Working with appropriate technology and facility personnel, the ISSO should arrange to relocate one of the name servers so that it resides on a different network segment than any other name server that hosts one or more of the same zones or ensure connectivity exists to allow for accessibility across subnets from hosts to existing name servers.
In cases where the zones are small and not subject to frequent change, consideration should be given to the use of hosts or lmhost files to resolve host names.'
  impact 0.7
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3425r5_chk'
  tag severity: 'high'
  tag gid: 'V-13043'
  tag rid: 'SV-13611r3_rule'
  tag stig_id: 'DNS0205'
  tag gtitle: 'Name Server network segment separation'
  tag fix_id: 'F-4348r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
