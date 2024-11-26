control 'SV-227541' do
  title 'The /usr/aset/userlist file must exist.'
  desc 'If the userlist file does not exist, then an unauthorized user may exist in the /etc/passwd file.'
  desc 'check', 'Determine if ASET is being used.
# crontab -l | grep aset
If ASET is not used on the system, this is not applicable.
If ASET is being used, but is not invoked with the "-u /usr/aset/userlist" option, this is a finding.

Check the /usr/aset/userlist file.
# ls -lL /usr/aset/userlist
If /usr/aset/userlist file does not exist, this is a finding.  An empty /usr/aset/userlist file, while not optimal, is not a finding.'
  desc 'fix', 'Create the /usr/aset/userlist file and populate it with a list of authorized users.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29703r488156_chk'
  tag severity: 'medium'
  tag gid: 'V-227541'
  tag rid: 'SV-227541r603266_rule'
  tag stig_id: 'GEN000000-SOL00220'
  tag gtitle: 'SRG-OS-000016'
  tag fix_id: 'F-29691r488157_fix'
  tag 'documentable'
  tag legacy: ['V-955', 'SV-955']
  tag cci: ['CCI-000032', 'CCI-000366']
  tag nist: ['AC-4 (8) (a)', 'CM-6 b']
end
