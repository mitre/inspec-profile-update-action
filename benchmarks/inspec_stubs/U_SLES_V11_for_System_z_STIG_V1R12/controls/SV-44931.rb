control 'SV-44931' do
  title 'All network services daemon files must have mode 0755 or less permissive.'
  desc 'Restricting permission on daemons will protect them from unauthorized modification and possible system compromise.'
  desc 'check', 'Check the mode of network services daemons.
# find /usr/sbin -type f -perm +022 -exec stat -c %a:%n {} \\;

This will return the octal permissions and name of all files that are group or world writable.
If any network services daemon listed is world or group writable (either or both of the 2 lowest order digits contain a 2, 3 or 6), this is a finding.
Note: Network daemons not residing in these directories (such as httpd or sshd) must also be checked for the correct permissions.'
  desc 'fix', 'Change the mode of the network services daemon.
# chmod go-w <path>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42367r1_chk'
  tag severity: 'medium'
  tag gid: 'V-786'
  tag rid: 'SV-44931r1_rule'
  tag stig_id: 'GEN001180'
  tag gtitle: 'GEN001180'
  tag fix_id: 'F-38358r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
