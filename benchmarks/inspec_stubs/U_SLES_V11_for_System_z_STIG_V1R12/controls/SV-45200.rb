control 'SV-45200' do
  title 'The system must be checked weekly for unauthorized setgid files as well as unauthorized modification to authorized setgid files.'
  desc 'Files with the setgid bit set will allow anyone running these files to be temporarily assigned the group id of the file. While many system files depend on these attributes for proper operation, security problems can result if setgid is assigned to programs allowing reading and writing of files, or shell escapes.'
  desc 'check', 'Determine if a weekly automated or manual process is used to generate a list of sgid files on the system and compare it with the prior list. If no such process is in place, this is a finding.

NOTE: For MAC I systems, increase the frequency to daily.'
  desc 'fix', 'Establish a weekly automated or manual process to generate a list of sgid files on the system and compare it with the prior list. To create a list of sgid files:
# find / -perm -2000 > suid-file-list

NOTE: For MAC I systems, increase the frequency to daily.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42548r2_chk'
  tag severity: 'medium'
  tag gid: 'V-804'
  tag rid: 'SV-45200r2_rule'
  tag stig_id: 'GEN002460'
  tag gtitle: 'GEN002460'
  tag fix_id: 'F-38596r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000318']
  tag nist: ['CM-3 f']
end
