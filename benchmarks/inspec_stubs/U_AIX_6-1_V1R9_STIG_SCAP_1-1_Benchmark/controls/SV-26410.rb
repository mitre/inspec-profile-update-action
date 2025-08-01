control 'SV-26410' do
  title 'The /etc/hosts file must be owned by root.'
  desc 'The /etc/hosts file (or equivalent) configures local host name to IP address mappings that typically take precedence over DNS resolution.  If this file is maliciously modified, it could cause the failure or compromise of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'fix', 'Change the owner of the /etc/hosts file to root.

# chown root /etc/hosts'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-22323'
  tag rid: 'SV-26410r2_rule'
  tag stig_id: 'GEN001366'
  tag gtitle: 'GEN001366'
  tag fix_id: 'F-23597r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
