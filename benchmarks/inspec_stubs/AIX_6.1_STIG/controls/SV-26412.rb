control 'SV-26412' do
  title 'The /etc/hosts file must have mode 0644 or less permissive.'
  desc 'The /etc/hosts file (or equivalent) configures local host name to IP address mappings that typically take precedence over DNS resolution.  If this file is maliciously modified, it could cause the failure or compromise of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', 'Check the mode of the /etc/hosts file.

Procedure:
# ls -l /etc/hosts
If the file mode is more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/hosts file to 0644 or less permissive.

# chmod 0644 /etc/hosts'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-27494r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22325'
  tag rid: 'SV-26412r1_rule'
  tag stig_id: 'GEN001368'
  tag gtitle: 'GEN001368'
  tag fix_id: 'F-23599r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
