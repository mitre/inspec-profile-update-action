control 'SV-53262' do
  title 'SQL Server must ensure, if Database Availability Groups are being used and there is a server failure, that none of the potential failover servers would suffer from resource exhaustion.'
  desc %q(SQL Server has a feature called 'Availability Group' which provides automatic failover from a primary SQL Server to a secondary server. This concept is not new, but because SQL Server does warn that if the secondary SQL Server is not dedicated 100% to being a backup server, that "resource exhaustion" may be an issue if there is some load balancing going on.

If the primary SQL Server has a backup/secondary server that is dedicated 100% to the primary server's process, this is not a finding. If, however, the processing of the primary SQL Server is loaded to a secondary server that is already partly resourced to process something other than that of the primary SQL Server responsibility, then there can be load balancing issues.

Load balancing for the purpose of sharing a secondary/backup SQL Server is often done to share and save on resources.)
  desc 'check', "If Database Availability Groups are not being used, this is not applicable (NA).

Check the system documentation and check with the administrator regarding processing resources of the backup/secondary SQL Server. 

If the primary SQL Server has a backup/secondary server that is dedicated 100% to the primary server's processing, this is not a finding.

If the secondary/backup SQL Server is already partly resourced to process something other than that of the primary SQL Server processing, then determine what resources would be required for the secondary/backup SQL Server.

If the secondary/backup SQL Server is determined to not have enough processing resources to fulfill the function of the primary server's SQL Server process, this is a finding."
  desc 'fix', 'Allocate replacement server(s) to provide failover support to the Primary SQL Server. 

If a single solution cannot be employed, split the processing of a secondary SQL Server amongst two or more secondary servers.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47563r3_chk'
  tag severity: 'medium'
  tag gid: 'V-40908'
  tag rid: 'SV-53262r3_rule'
  tag stig_id: 'SQL2-00-022400'
  tag gtitle: 'SRG-APP-000248-DB-000135'
  tag fix_id: 'F-46190r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002394']
  tag nist: ['SC-6']
end
