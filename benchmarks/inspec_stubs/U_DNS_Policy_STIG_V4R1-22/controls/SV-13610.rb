control 'SV-13610' do
  title 'An authoritative master name server does not have at least one and preferably two or more active slave servers for each of its zones. The slave server does not reside on a separate host.'
  desc 'A critical component of securing an information system is ensuring its availability.  The best way to ensure availability is to eliminate any single point of failure in the system itself and in the network architecture that supports it.

Fortunately, the inherent design of DNS supports a high-availability environment.  Master and slave servers regularly communicate zone information, so if any name server is disabled at any time, another can immediately provide the same service.  The task for the network architect is to ensure that a disaster or outage cannot simultaneously impact both the master and all of its slave servers.  If a disaster occurs, the DNS protocols cannot prevent total loss of name resolution services for hosts within affected zones.'
  desc 'check', 'The intent of this check is to ensure zone queries can be answered in the event of failure of the primary name server. By requiring at least one other name server, queries will still be answered by one name server in the event of another name server failure.

Using the name server configuration files, identify any zone that does not have multiple name servers.  An authoritative server for each zone must have more than one name server.  

If there is only one name server for a zone, this is a finding. 

If the secondary server does not reside on a separate host, this is a finding.  

Windows (with Active Directory)
For servers integrated with Active Directory, verify there are other domain controllers that can take over as Domain naming operations master.  Open the Active Users and Computer snap in console under the Administrative tools menu.  Expand the active directory domain and then expand the domain controllers folder.  Ensure there are multiple domain controllers available within the domain.
   
BIND
Examine each zone file and check the NS records.  There should be multiple records for the same domain with different servers authoritative for the zone.  The path to the zone file can be found by examining the named.conf.'
  desc 'fix', 'The ISSO must work with appropriate personnel to obtain and configure another name server to act as a slave to the server hosting this zone.'
  impact 0.7
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3424r3_chk'
  tag severity: 'high'
  tag gid: 'V-13042'
  tag rid: 'SV-13610r2_rule'
  tag stig_id: 'DNS0200'
  tag gtitle: 'No slave server exists for authoritative master.'
  tag fix_id: 'F-4347r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
