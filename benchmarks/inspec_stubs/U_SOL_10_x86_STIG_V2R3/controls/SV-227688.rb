control 'SV-227688' do
  title 'All .rhosts, .shosts, or host.equiv files must only contain trusted host-user pairs.'
  desc 'If these files are not properly configured, they could allow malicious access by unknown malicious users from untrusted hosts who could compromise the system.'
  desc 'check', %q(Locate and examine all .rhosts, .shosts, hosts.equiv, and shosts.equiv files.  The .rhosts and .shosts files are stored in home directories.  (If a user does not have a home directory assigned in /etc/passwd, the root directory (/) is assigned as a default home directory.)

Procedure:
# for i in `cut -d: -f6 /etc/passwd | awk '$1 == "" {$1 = "/"} {print $1}'`; do more $i/.rhosts; more $i/.shosts; done
# more /etc/hosts.equiv
# more /etc/ssh/shosts.equiv

If any .rhosts, .shosts, hosts.equiv, or shosts.equiv file contains other than host-user pairs, this is a finding.)
  desc 'fix', 'If possible, remove the .rhosts, .shosts, hosts.equiv, and shosts.equiv files.  If the files are required, remove any content from the files except for necessary host-user pairs.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29850r488645_chk'
  tag severity: 'medium'
  tag gid: 'V-227688'
  tag rid: 'SV-227688r603266_rule'
  tag stig_id: 'GEN002020'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29838r488646_fix'
  tag 'documentable'
  tag legacy: ['V-4427', 'SV-40331']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
