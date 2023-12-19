control 'SV-218285' do
  title 'The /etc/hosts file must have mode 0644 or less permissive.'
  desc 'The /etc/hosts file (or equivalent) configures local host name to IP address mappings that typically take precedence over DNS resolution.  If this file is maliciously modified, it could cause the failure or compromise of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', 'Check the mode of the /etc/hosts file.
# ls -l /etc/hosts

If the file mode is not 0644, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/hosts file to 0644.

# chmod 0644 /etc/hosts'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19760r568813_chk'
  tag severity: 'medium'
  tag gid: 'V-218285'
  tag rid: 'SV-218285r603259_rule'
  tag stig_id: 'GEN001368'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19758r568814_fix'
  tag 'documentable'
  tag legacy: ['V-22325', 'SV-64527']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
