control 'SV-218347' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19822r554378_chk'
  tag severity: 'medium'
  tag gid: 'V-218347'
  tag rid: 'SV-218347r603259_rule'
  tag stig_id: 'GEN002020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19820r554379_fix'
  tag 'documentable'
  tag legacy: ['V-4427', 'SV-63611']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
