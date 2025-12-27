control 'SV-13606' do
  title 'Operating procedures do not require that DNS configuration, keys, zones, and resource record data are backed up on any day on which there are changes.'
  desc 'If a name servers configuration, keys, zones, and resource record information is not backed up on any day in which there are changes, there is a risk that an organization cannot quickly recover from the loss of the server.  In addition, forensic analysis of security incidents is considerably more difficult if there is not reliable evidence of when changes may have occurred.'
  desc 'check', 'Fortunately, by design, the DNS architecture provides built-in redundancy support.  There should always be a hot backup of zone information present whenever the primary name server is unavailable for any reason (i.e., the authoritative slave server maintains a copy of the zone files on the master).  This built-in redundancy, however, does not extend to configuration files and logs.  Therefore, name servers should be backed up to an external media (e.g., tape, optical disk, etc.) on a regular basis.

At some locations, an automated enterprise backup system supports many servers.  In this case, name servers can simply be added to the enterprise system.  At other locations, backups must be performed manually, placing a considerably higher burden on administrators.  In circumstances in which zone and configuration information is very static, remaining the same for several months at a time, it would make little sense to conduct daily full backups.  Backups should occur as frequently as needed to capture changes on the name server.

If there are no written procedures for the backup of name servers, then this is a finding.  Backup in this context refers to copying the name server’s DNS configuration, keys, zones,  and resource record data, at a minimum, in case it is needed for recovery at a later time.  A full file system backup of the name server is preferred.

If there are written backup procedures, then it must call for the backup of DNS configuration, keys, zones, and resource record data on any day in which they were modified, it this is not the case, then this is a finding.  

Any traditional daily tape backup scheme – whether it involves a full, incremental or differential scheme – will satisfy the requirement.  Less frequent backups will also suffice if the configuration and resource record data are backed up whenever they are modified.'
  desc 'fix', 'The IAO will establish operating procedures that will ensure that, at a minimum, DNS configuration, keys, zones, and resource record data is backed up on any day on which there are changes.'
  impact 0.5
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3361r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13038'
  tag rid: 'SV-13606r1_rule'
  tag stig_id: 'DNS0135'
  tag gtitle: 'Operating procedures do not require backup.'
  tag fix_id: 'F-4343r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
