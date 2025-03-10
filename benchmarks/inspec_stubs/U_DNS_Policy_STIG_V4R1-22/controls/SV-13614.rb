control 'SV-13614' do
  title 'The DNS database administrator has not documented the owner of each zone (or group of related records) and the date the zone was created, last modified, or verified.  This documentation will preferably reside in the zone file itself through comments, but if this is not feasible, the DNS database administrator will maintain a separate database for this purpose.'
  desc 'A zone file should contain adequate documentation that would allow an IAO or newly assigned administrator to quickly learn the scope and structure of that zone.  In particular, each record (or related set of records, such as a group of LAN workstations) should be accompanied by a notation of the date the record was created, modified, or validated and record the owner’s name, title, and organizational affiliation.  The owner of a record is an individual with the authority to request that the record be modified or deleted.

If an organization cannot identify who is responsible for a host record, then there is no assurance that it is valid.  If invalid records are in a zone, then an adversary could potentially use their existence for improper purposes.'
  desc 'check', 'BIND 
DNS zone record documentation will preferably reside in the zone file itself through comments, but if this is not feasible, the DNS database administrator will maintain a separate database for this purpose. The zone file location can be found by examining the named.conf and searching for the zone statement.  Within the zone statement will be a file option that will display the name of the zone file.

Windows 
Ask the DNS database administrator if they maintain a separate database with record documentation.  Windows DNS does not provide the capability to insert comments for records in a zone.  

Review the zone files/database. If the records are not fully documented, then this is a finding.  The zone record documentation is to include, at a minimum:

-	The owner of each zone record
-	The date the zone record was created
-	The date the zone record was last modified
-	The date the zone record was last verified

Records can be grouped (e.g., a number of workstations residing in the same area or a high-availability server cluster)'
  desc 'fix', 'The DNS database administrator will document, at a minimum, the owner of each zone record (or group of related records) and the date the record was created, last modified, or verified.  This documentation will preferably reside in the zone file itself through comments, but if this is not feasible, the DNS database administrator will maintain a separate database for this purpose.'
  impact 0.3
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3429r1_chk'
  tag severity: 'low'
  tag gid: 'V-13046'
  tag rid: 'SV-13614r1_rule'
  tag stig_id: 'DNS0220'
  tag gtitle: 'Zone records are not adequately documented.'
  tag fix_id: 'F-4351r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
