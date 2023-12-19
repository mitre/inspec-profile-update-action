control 'SV-227689' do
  title 'There must be no .rhosts, .shosts, hosts.equiv, or shosts.equiv files on the system.'
  desc 'The .rhosts, .shosts, hosts.equiv, and shosts.equiv files are used to configure host-based authentication for individual users or the system.  Host-based authentication is not sufficient for preventing unauthorized access to the system.'
  desc 'check', %q(Check for the existence of the files.  The .rhosts and .shosts files are stored in home directories.  (If a user does not have a home directory assigned in /etc/passwd, the root directory (/) is assigned as a default home directory.)

Procedure (the first command is five lines long):
# for homedir in `cut -d: -f6 /etc/passwd | awk '$1 == "" {$1 = "/"} {print $1}'`;
     do
        ls -l $homedir/.rhosts;
        ls -l $homedir/.shosts;
     done
# ls -l /etc/hosts.equiv
# ls -l /etc/ssh/shosts.equiv

If .rhosts, .shosts, hosts.equiv, or shosts.equiv are found, this is a finding.)
  desc 'fix', 'Remove the .rhosts, .shosts, hosts.equiv, and/or shosts.equiv files.'
  impact 0.7
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29851r488648_chk'
  tag severity: 'high'
  tag gid: 'V-227689'
  tag rid: 'SV-227689r603266_rule'
  tag stig_id: 'GEN002040'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29839r488649_fix'
  tag 'documentable'
  tag legacy: ['V-11988', 'SV-40332']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
