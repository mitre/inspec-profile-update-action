control 'SV-32245' do
  title 'System information backups will be created, updated, and protected.'
  desc 'Recovery of a damaged or compromised system in a timely basis is difficult without a system information backup.  A system backup will usually include sensitive information such as user accounts that could be used in an attack.  As a valuable system resource, the system backup should be protected and stored in a physically secure location.'
  desc 'check', 'Interview the SA to determine if system recovery backup procedures are in place that comply with DoD requirements.

Any of the following would be a finding:

-The site does not maintain emergency system recovery data.
-The emergency system recovery data is not protected from destruction and stored in a locked storage container. 
-The emergency system recovery data has not been updated following the last system modification.'
  desc 'fix', 'Implement backup procedures that comply with the following requirements:   

-Maintain emergency system recovery data.
-The emergency system recovery data is protected from destruction and stored in a locked storage container. 
-The emergency system recovery data is updated following the last system modification.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32877r1_chk'
  tag severity: 'low'
  tag gid: 'V-1076'
  tag rid: 'SV-32245r1_rule'
  tag gtitle: 'System Recovery Backups'
  tag fix_id: 'F-29349r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
