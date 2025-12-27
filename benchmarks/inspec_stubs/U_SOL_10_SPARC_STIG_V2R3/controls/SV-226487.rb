control 'SV-226487' do
  title 'All network services daemon files must have mode 0755 or less permissive.'
  desc 'Restricting permission on daemons will protect them from unauthorized modification and possible system compromise.'
  desc 'check', "Check the mode of network services daemons.
# ls -la /usr/bin /usr/sbin
If the mode of a network services daemon is more permissive than 0755, this is a finding.
NOTE: Network daemons not residing in these directories (such as httpd or sshd) must also be checked for the correct permissions.

A way to locate network daemons, such as httpd and sshd, is with the ps command.
# ps -ef | egrep '(sshd|httpd)'"
  desc 'fix', 'Change the mode of the network services daemon.
# chmod 0755 <path>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28648r482846_chk'
  tag severity: 'medium'
  tag gid: 'V-226487'
  tag rid: 'SV-226487r854407_rule'
  tag stig_id: 'GEN001180'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-28636r482847_fix'
  tag 'documentable'
  tag legacy: ['V-786', 'SV-27161']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
