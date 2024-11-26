control 'SV-227708' do
  title 'The system must be checked weekly for unauthorized setgid files, as well as, unauthorized modification to authorized setgid files.'
  desc 'Files with the setgid bit set will allow anyone running these files to be temporarily assigned the group id of the file. While many system files depend on these attributes for proper operation, security problems can result if setgid is assigned to programs that allow reading and writing of files, or shell escapes.'
  desc 'check', 'Determine if a weekly automated or manual process is used to generate a list of setgid files on the system and compare it with the prior list.  If no such process is in place, this is a finding.'
  desc 'fix', 'Establish a weekly automated or manual process to generate a list of setgid files on the system and compare it with the prior list.  To create a list of setgid files use the following command.
# find / -perm -2000 > setgid-file-list'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29870r488708_chk'
  tag severity: 'medium'
  tag gid: 'V-227708'
  tag rid: 'SV-227708r603266_rule'
  tag stig_id: 'GEN002460'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-29858r488709_fix'
  tag 'documentable'
  tag legacy: ['V-804', 'SV-804']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
