control 'SV-226580' do
  title 'The system must be checked weekly for unauthorized setuid files, as well as, unauthorized modification to authorized setuid files.'
  desc 'Files with the setuid bit set will allow anyone running these files to be temporarily assigned the UID of the file. While many system files depend on these attributes for proper operation, security problems can result if setuid is assigned to programs that allow reading and writing of files, or shell escapes.'
  desc 'check', 'Determine if a weekly automated or manual process is used to generate a list of setuid files on the system and compare it with the prior list.  If no such process is in place, this is a finding.'
  desc 'fix', 'Establish a weekly automated or manual process to generate a list of setuid files on the system and compare it with the prior list.  To create a list of setuid files use the following command.
# find / -perm -4000 > setuid-file-list'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28741r483149_chk'
  tag severity: 'medium'
  tag gid: 'V-226580'
  tag rid: 'SV-226580r603265_rule'
  tag stig_id: 'GEN002400'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-28729r483150_fix'
  tag 'documentable'
  tag legacy: ['V-803', 'SV-803']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
