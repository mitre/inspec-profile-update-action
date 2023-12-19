control 'SV-227632' do
  title 'The /etc/hosts file must be owned by root.'
  desc 'The /etc/hosts file (or equivalent) configures local host name to IP address mappings that typically take precedence over DNS resolution.  If this file is maliciously modified, it could cause the failure or compromise of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', 'Verify the /etc/hosts file is owned by root.

Procedure:
# ls -lL /etc/hosts
If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/hosts file to root.

# chown root /etc/hosts'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29794r488456_chk'
  tag severity: 'medium'
  tag gid: 'V-227632'
  tag rid: 'SV-227632r603266_rule'
  tag stig_id: 'GEN001366'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29782r488457_fix'
  tag 'documentable'
  tag legacy: ['V-22323', 'SV-26410']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
