control 'SV-38473' do
  title 'The system must be checked weekly for unauthorized setgid files as well as unauthorized modification to authorized setgid files.'
  desc 'Files with the setgid bit set will allow anyone running these files to be temporarily assigned the group id of the file. While many system files depend on these attributes for proper operation, security problems can result if setgid is assigned to programs that allow reading and writing of files, or shell escapes.'
  desc 'check', 'NOTE: This will virtually always require a manual review. Determine if a weekly automated or manual process is used to generate a list of sgid files on the system and compare it with the prior list. If no such process is in place, this is a finding.'
  desc 'fix', 'Establish a weekly automated or manual process to generate a list of sgid files on the system and compare it with the prior list. To create a list of sgid files:

# find / -type f -perm -2000 -exec ls -lL {} \\; >> sgid-file-list'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36402r1_chk'
  tag severity: 'medium'
  tag gid: 'V-804'
  tag rid: 'SV-38473r1_rule'
  tag stig_id: 'GEN002460'
  tag gtitle: 'GEN002460'
  tag fix_id: 'F-31741r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-000318']
  tag nist: ['CM-3 f']
end
