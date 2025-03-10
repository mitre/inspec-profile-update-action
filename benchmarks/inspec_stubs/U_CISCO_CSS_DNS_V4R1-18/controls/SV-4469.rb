control 'SV-4469' do
  title 'Zone-spanning CNAME records, that point to a zone with lesser security, are active for more than six months.'
  desc 'The use of CNAME records for exercises, tests or zone-spanning aliases should be temporary (e.g., to facilitate a migration).  When a host name is an alias for a record in another zone, an adversary has two points of attack  the zone in which the alias is defined and the zone authoritative for the aliases canonical name.  This configuration also reduces the speed of client resolution because it requires a second lookup after obtaining the canonical name. Furthermore, in the case of an authoritative name server, this information is promulgated throughout the enterprise to caching servers and thus compounding the vulnerability.'
  desc 'check', 'BIND
The zone file location can be found by examining the named.conf and searching for the zone statement.  Within the zone statement will be a file option that will display the name of the zone file.  The record type column will display CNAME.  This is usually the third or fourth field in a record depending if the TTL value is utilized.  Without a TTL value, the CNAME type will be in the third field, otherwise it will display as the fourth field.  Review the zone files and the DNS zone record documentation to confirm that there are no CNAME records, pointing to a zone with lesser security, older than 6 months.  

The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms. In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated.

If there are zone-spanning CNAME records older than 6 months and the CNAME records resolve to anything other than fully qualified domain names for glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms with an AO-approved and documented mission need, this is a finding.

Windows
Open the DNS management snap in for the Administrative Tools menu.  Expand the Forward Lookup Zones folder.  Review the type column for each record to locate those with a type of Alias (CNAME).  Ask the DNS administrator to see the database with the record documentation is stored to confirm there are not CNAME records, pointing to a zone with lesser security, older than 6 months. 

The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms. In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated.

If there are zone-spanning CNAME records older than 6 months and the CNAME records resolve to anything other than fully qualified domain names for glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms with an AO-approved and documented mission need, this is a finding.'
  desc 'fix', 'The DNS database administrator should remove any zone-spanning CNAME records that have been active for more than six months.'
  impact 0.3
  ref 'DPMS Target Cisco CSS DNS'
  tag check_id: 'C-3432r3_chk'
  tag severity: 'low'
  tag gid: 'V-4469'
  tag rid: 'SV-4469r3_rule'
  tag stig_id: 'DNS0235'
  tag gtitle: 'A CNAME record has been active too long.'
  tag fix_id: 'F-4354r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
