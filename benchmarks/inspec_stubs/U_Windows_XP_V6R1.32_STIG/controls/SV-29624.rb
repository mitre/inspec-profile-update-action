control 'SV-29624' do
  title 'System information backups are not created, updated, and protected according to DISA requirements.'
  desc 'Recovery of a damaged or compromised system in a timely basis is difficult without a system information backup.  A system backup will usually include sensitive information such as user accounts that could be used in an attack.  As a valuable system resource, the system backup should be protected and stored in a physically secure location.'
  desc 'check', 'Interview the SA to determine if system recovery backup procedures are in place that comply with DoD requirements.

Any of the following would be a finding:

•The site does not maintain emergency system recovery data.
•The emergency system recovery data is not protected from destruction and stored in a locked storage container. 
•The emergency system recovery data has not been updated following the last system modification.'
  desc 'fix', 'Implement data backup procedures that comply with DoD requirements.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-7887r1_chk'
  tag severity: 'low'
  tag gid: 'V-1076'
  tag rid: 'SV-29624r1_rule'
  tag gtitle: 'System Recovery Backups'
  tag fix_id: 'F-36r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'CODB-1'
end
