control 'SV-227685' do
  title 'User start-up files must not execute world-writable programs.'
  desc 'If start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to become Trojans destroying user files or otherwise compromising the system at the user, or higher, level.  If the system is compromised at the user level, it is much easier to eventually compromise the system at the root and network level.'
  desc 'check', "Check local initialization files for any executed world-writable programs or scripts.

Procedure:
# find / -perm -002 -type f | egrep -v '^(/proc|/system/contract)' > wwlist
# fgrep -f wwlist /<usershomedirectory>/.*

If any local initialization file executes a world-writable program or script, this is a finding."
  desc 'fix', 'Remove the world-writable permission of files referenced by local initialization scripts, or remove the references to these files in the local initialization scripts.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29847r488636_chk'
  tag severity: 'medium'
  tag gid: 'V-227685'
  tag rid: 'SV-227685r603266_rule'
  tag stig_id: 'GEN001940'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29835r488637_fix'
  tag 'documentable'
  tag legacy: ['V-4087', 'SV-39812']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
