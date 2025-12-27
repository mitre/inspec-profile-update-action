control 'SV-45166' do
  title 'All .rhosts, .shosts, or host.equiv files must only contain trusted host-user pairs.'
  desc 'If these files are not properly configured, they could allow malicious access by unknown malicious users from untrusted hosts who could compromise the system.'
  desc 'check', 'Locate and examine all r-commands access control files.

Procedure:
# find / -name .rhosts
# more /<directorylocation>/.rhosts

# find / -name .shosts
# more /<directorylocation>/.shosts

# find / -name hosts.equiv
# more /<directorylocation>/hosts.equiv

# find / -name shosts.equiv
# more /<directorylocation>/shosts.equiv

If any .rhosts, .shosts, hosts.equiv, or shosts.equiv file contains other than host-user pairs, this is a finding.'
  desc 'fix', 'If possible, remove the .rhosts, .shosts, hosts.equiv, and shosts.equiv files. If the files are required, remove any content from the files except for necessary host-user pairs.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42510r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4427'
  tag rid: 'SV-45166r1_rule'
  tag stig_id: 'GEN002020'
  tag gtitle: 'GEN002020'
  tag fix_id: 'F-38563r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
