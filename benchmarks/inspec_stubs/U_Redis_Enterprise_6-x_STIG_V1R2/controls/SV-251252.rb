control 'SV-251252' do
  title 'When updates are applied to Redis Enterprise DBMS software, any software components that have been replaced or made unnecessary must be removed.'
  desc "Previous versions of DBMS components that are not removed from the information system after updates have been installed may be exploited by adversaries. 

Some DBMSs' installation tools may remove older versions of software automatically from the information system. In other cases, manual review and removal will be required. In planning installations and upgrades, organizations must include steps (automated, manual, or both) to identify and remove the outdated modules.

A transition period may be necessary when both the old and the new software are required. This should be considered in the planning."
  desc 'check', 'When the Redis software is upgraded to a new version, the old version install file remains on the server. The users must remove this manually. To verify if the old install files have been deleted, check the locations below:
/opt/redislabs - Main Installation directory for all Redis Enterprise Software binaries
/opt/redislabs/config - System configuration files
/opt/redislabs/lib - System library files
/var/opt/redislabs - Default storage location for the cluster data, system logs, backups and ephemeral, persisted data
/tmp - Temporary files

The GREP command can be used to search for old Redis files in the above locations. 

If software components that have been replaced or made unnecessary are not removed, this is a finding.'
  desc 'fix', 'When a new update is available and installed, all old install files must be removed from the locations below:
/opt/redislabs - Main Installation directory for all Redis Enterprise Software binaries
/opt/redislabs/config - System configuration files
/opt/redislabs/lib - System library files
/var/opt/redislabs - Default storage location for the cluster data, system logs, backups and ephemeral, persisted data
/tmp - Temporary files

The GREP command can be used to search for old Redis files in the above locations.

If software from a previous/outdated version of Redis Enterprise remains in any of the following locations/directories, run the following to remove it: 
rm -r <file_name>'
  impact 0.3
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54687r804944_chk'
  tag severity: 'low'
  tag gid: 'V-251252'
  tag rid: 'SV-251252r855625_rule'
  tag stig_id: 'RD6X-00-012400'
  tag gtitle: 'SRG-APP-000454-DB-000389'
  tag fix_id: 'F-54641r804945_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
