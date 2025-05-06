control 'SV-39502' do
  title 'All .rhosts, .shosts, .netrc, or hosts.equiv files must be accessible by only root or the owner.'
  desc 'If these files are accessible by users other than root or the owner, they could be used by a malicious user to set up a system compromise.'
  desc 'check', '# find / -type f -name .rhosts
# ls -alL /<directorylocation>/.rhosts

# find / -type f -name .shosts
# ls -alL /<directorylocation>/.shosts

# find / -type f -name hosts.equiv
# ls -lL /<directorylocation>/hosts.equiv

# find / -type f -name shosts.equiv
# ls -lL /<directorylocation>/shosts.equiv

If the .rhosts, .shosts, hosts.equiv, or shosts.equiv files have permissions greater than 700, this is a finding.'
  desc 'fix', 'Ensure the permission for these files is set at 700 or less and the owner is the owner of the home directory that it is in.  These files, outside of home directories (other than hosts.equiv which is in /etc and owned by root), have no meaning.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-8220r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4428'
  tag rid: 'SV-39502r1_rule'
  tag stig_id: 'GEN002060'
  tag gtitle: 'GEN002060'
  tag fix_id: 'F-4327r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
