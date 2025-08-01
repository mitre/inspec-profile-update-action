control 'SV-227635' do
  title 'The /etc/hosts file must not have an extended ACL.'
  desc 'The /etc/hosts file (or equivalent) configures local host name to IP address mappings that typically take precedence over DNS resolution.  If this file is maliciously modified, it could cause the failure or compromise of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', 'Verify /etc/hosts has no extended ACL.
# ls -lL /etc/hosts
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/hosts'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29797r488465_chk'
  tag severity: 'medium'
  tag gid: 'V-227635'
  tag rid: 'SV-227635r603266_rule'
  tag stig_id: 'GEN001369'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29785r488466_fix'
  tag 'documentable'
  tag legacy: ['V-22326', 'SV-26415']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
