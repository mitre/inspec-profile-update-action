control 'SV-218349' do
  title 'All .rhosts, .shosts, .netrc, or hosts.equiv files must be accessible by only root or the owner.'
  desc 'If these files are accessible by users other than root or the owner, they could be used by a malicious user to set up a system compromise.'
  desc 'check', 'Procedure:
# ls -l /etc/hosts.equiv

# ls -l /etc/ssh/shosts.equiv

# find / -name .rhosts
# ls -al <home directory>/.rhosts

# find / -name .shosts
# ls -al <home directory>/.shosts

# find / -name .netrc
# ls -al <home directory>/.netrc

If the .rhosts, .shosts, hosts.equiv, or shosts.equiv files have permissions greater than 600, then this is a finding.
If the /etc/hosts.equiv, or /etc/ssh/shosts.equiv files are not owned by root, this is a finding.

Any .rhosts, .shosts and .netrc files outside of home directories have no meaning and are not subject to this rule
If the ~/.rhosts or ~/.shosts are not owned by the owner of the home directory where they are immediately located or by root, this is a finding.'
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19824r569026_chk'
  tag severity: 'medium'
  tag gid: 'V-218349'
  tag rid: 'SV-218349r603259_rule'
  tag stig_id: 'GEN002060'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19822r569027_fix'
  tag 'documentable'
  tag legacy: ['V-4428', 'SV-63635']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
