control 'SV-218283' do
  title 'The /etc/hosts file must be owned by root.'
  desc 'The /etc/hosts file (or equivalent) configures local host name to IP address mappings that typically take precedence over DNS resolution.  If this file is maliciously modified, it could cause the failure or compromise of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', 'Verify the /etc/hosts file is owned by root.
# ls -l /etc/hosts

If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/hosts file to root.
# chown root /etc/hosts'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19758r568807_chk'
  tag severity: 'medium'
  tag gid: 'V-218283'
  tag rid: 'SV-218283r603259_rule'
  tag stig_id: 'GEN001366'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19756r568808_fix'
  tag 'documentable'
  tag legacy: ['V-22323', 'SV-64519']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
