control 'SV-1029' do
  title 'The /etc/smbpasswd file must be owned by root.'
  desc 'If the smbpasswd file is not owned by root, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check the ownership of the smbpasswd file.

# find / -name smbpasswd
# ls -l <smbpasswd file>

If an smbpasswd file is not owned by root, this is a finding.'
  desc 'fix', 'Use the chown command to configure the smbpasswd file.
# chown root /etc/smbpasswd'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28774r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1029'
  tag rid: 'SV-1029r2_rule'
  tag stig_id: 'GEN006160'
  tag gtitle: 'GEN006160'
  tag fix_id: 'F-1183r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
