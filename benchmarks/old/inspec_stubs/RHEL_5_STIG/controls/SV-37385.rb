control 'SV-37385' do
  title 'All .rhosts, .shosts, .netrc, or hosts.equiv files must be accessible by only root or the owner.'
  desc 'If these files are accessible by users other than root or the owner, they could be used by a malicious user to set up a system compromise.'
  desc 'fix', 'Ensure the permission for these files is set to 600 or more restrictive and their owner is root or the same as the owner of the home directory in which they reside.

Procedure:
# chmod 600 /etc/hosts.equiv
# chmod 600 /etc/ssh/shosts.equiv
# chown root /etc/hosts.equiv
# chown root /etc/ssh/shosts.equiv

# find / -name .rhosts
# chmod 600 /<home directory>/.rhosts
# chown <home directory owner> <home directory>/.rhosts

# find / -name .shosts
# chmod 600 <directory location>/.shosts
# chown <home directory owner> <home directory>/.shosts

# find / -name .netrc
# chmod 600 <directory location>/.netrc
# chown <home directory owner> <home directory>/.netrc'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-4428'
  tag rid: 'SV-37385r1_rule'
  tag stig_id: 'GEN002060'
  tag gtitle: 'GEN002060'
  tag fix_id: 'F-31316r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
