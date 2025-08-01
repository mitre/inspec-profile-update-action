control 'SV-226564' do
  title 'All .rhosts, .shosts, .netrc, or hosts.equiv files must be accessible by only root or the owner.'
  desc 'If these files are accessible by users other than root or the owner, they could be used by a malicious user to set up a system compromise.'
  desc 'check', %q(# for i in `cut -d: -f6 /etc/passwd | awk '$1 == "" {$1 = "/"} {print $1}'`; do ls -l $i/.rhosts $i/.shosts $i/.netrc; done
# ls -l /etc/hosts.equiv
# ls -l /etc/ssh/shosts.equiv

If the .netrc, .rhosts, .shosts, hosts.equiv, or shosts.equiv files have permissions greater than 600, then this is a finding.  (If a password entry has no home directory assigned, the root directory (/) is used as a default.))
  desc 'fix', 'Ensure the permission for these files is set at 600 or less and the owner is the owner of the home directory that it is in. These files, outside of home directories (other than hosts.equiv in /etc and shosts.equiv in /etc/ssh; both are owned by root), have no meaning.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36391r602776_chk'
  tag severity: 'medium'
  tag gid: 'V-226564'
  tag rid: 'SV-226564r603265_rule'
  tag stig_id: 'GEN002060'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36355r602777_fix'
  tag 'documentable'
  tag legacy: ['V-4428', 'SV-40341']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
