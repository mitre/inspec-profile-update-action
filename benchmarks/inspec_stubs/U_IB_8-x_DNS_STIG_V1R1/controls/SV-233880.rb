control 'SV-233880' do
  title 'CNAME records must not point to a zone with lesser security for more than six months.'
  desc "The use of CNAME records for exercises, tests, or zone-spanning aliases should be temporary (e.g., to facilitate a migration). When a host name is an alias for a record in another zone, an adversary has two points of attack: the zone in which the alias is defined and the zone authoritative for the alias's canonical name. 

This configuration also reduces the speed of client resolution because it requires a second lookup after obtaining the canonical name. Furthermore, in the case of an authoritative name server, this information is promulgated throughout the enterprise to caching servers and thus compounds the vulnerability."
  desc 'check', 'Infoblox DNS records the creation date of every resource record, including CNAME records in the system, and the TimeStamp is attached to the CNAME object. Infoblox can also record the date of the last time this record was used or queried. CNAME records can be removed by the administrator when they reach their six-month maturity date.  

1. Navigate to Grid Manager >> Administration >> Logs >> Audit Log. Click "Show Filter" if it is not already displayed. 
2. Create a new search using "Object Type equals CNAME Record".  
3. Click the plus symbol to add a second search parameter. 
4. Create an additional search parameter, "Timestamp before YYYY-MM-DD", using the calendar selection box to choose the appropriate date six months prior to the current date.  
5. Click "Apply" to display CNAME records created more than six months ago. 

If there are zone-spanning CNAME records older than six months and the CNAME records resolve to anything other than fully qualified domain names for glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms with an AO-approved and documented mission need, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Zones. 
2. Edit the zone containing CNAME records discovered during review of the Audit Log.
3. Remove any zone-spanning CNAME records that have been active for more than six months.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37065r611160_chk'
  tag severity: 'medium'
  tag gid: 'V-233880'
  tag rid: 'SV-233880r621666_rule'
  tag stig_id: 'IDNS-8X-400022'
  tag gtitle: 'SRG-APP-000516-DNS-000114'
  tag fix_id: 'F-37030r611161_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
