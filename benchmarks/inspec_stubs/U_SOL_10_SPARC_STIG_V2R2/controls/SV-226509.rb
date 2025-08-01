control 'SV-226509' do
  title 'The /etc/hosts file must not have an extended ACL.'
  desc 'The /etc/hosts file (or equivalent) configures local host name to IP address mappings that typically take precedence over DNS resolution.  If this file is maliciously modified, it could cause the failure or compromise of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', 'Verify /etc/hosts has no extended ACL.
# ls -lL /etc/hosts
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/hosts'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28670r482915_chk'
  tag severity: 'medium'
  tag gid: 'V-226509'
  tag rid: 'SV-226509r603265_rule'
  tag stig_id: 'GEN001369'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28658r482916_fix'
  tag 'documentable'
  tag legacy: ['V-22326', 'SV-26415']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
