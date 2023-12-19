control 'SV-48019' do
  title 'System information backups must be created, updated, and protected.'
  desc 'Recovery of a damaged or compromised system in a timely manner is difficult without a system information backup.  A system backup will usually include sensitive information such as user accounts that could be used in an attack.  As a valuable system resource, the system backup must be protected and stored in a physically secure location.'
  desc 'check', 'Determine if system recovery backup procedures are in place that comply with DoD requirements.

Any of the following would be a finding:

-The site does not maintain emergency system recovery data.
-The emergency system recovery data is not protected from destruction and stored in a locked storage container. 
-The emergency system recovery data has not been updated following the last system modification.'
  desc 'fix', 'Implement system recovery procedures that include maintaining emergency system recovery data, protecting that data from destruction and storing it in a locked storage container, and updating it following each and every system modification.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44757r2_chk'
  tag severity: 'low'
  tag gid: 'V-1076'
  tag rid: 'SV-48019r1_rule'
  tag stig_id: 'WN08-00-000003'
  tag gtitle: 'System Recovery Backups'
  tag fix_id: 'F-41157r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
