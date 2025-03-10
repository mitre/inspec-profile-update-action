control 'SV-4467' do
  title 'Record owners will validate their zones no less than annually.  The DNS database administrator will remove all zone records that have not been validated in over a year.'
  desc 'If zone information has not been validated in over a year, then there is no assurance that it is still valid.  If invalid records are in a zone, then an adversary could potentially use their existence for improper purposes. An SOP detailing this process can resolve this requirement.'
  desc 'check', 'BIND
DNS zone record documentation will preferably reside in the zone file itself through comments, but if this is not feasible, the DNS database administrator will maintain a separate database for this purpose. The zone file location can be found by examining the named.conf and searching for the zone statement.  Within the zone statement will be a file option that will display the name of the zone file.  The reviewer should check that the record’s last verified date is less than one year prior to the date of the review.  If this is not the case for any host or group of hosts, then this is a finding.

Windows
Ask the DNS database administrator if they maintain a separate database with record documentation.  Windows DNS does not provide the capability to insert comments for records in a zone.  The reviewer should check that the record’s last verified date is less than one year prior to the date of the review.  If this is not the case for any host or group of hosts, then this is a finding.'
  desc 'fix', 'Working with DNS Administrators and other appropriate technical personnel, the IAO should attempt to validate the hosts with expired validation dates.  If these cannot be validated within a reasonable period of time, they should be removed.

A zone file should contain adequate documentation that would allow an IAO or newly assigned administrator to quickly learn the scope and structure of that zone.  In particular, each record (or related set of records, such as a group of LAN workstations) should be accompanied by a notation of the date the record was created, modified, or validated and record the owner’s name, title, and organizational affiliation.  The owner of a record is an individual with the authority to request that the record be modified or deleted.'
  impact 0.3
  ref 'DPMS Target Cisco CSS DNS'
  tag check_id: 'C-3430r1_chk'
  tag severity: 'low'
  tag gid: 'V-4467'
  tag rid: 'SV-4467r2_rule'
  tag stig_id: 'DNS0225'
  tag gtitle: 'A zone record has not been validated.'
  tag fix_id: 'F-4352r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1'
end
