control 'SV-35225' do
  title 'The smbpasswd file must be owned by root.'
  desc 'If the smbpasswd file is not owned by root, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check the ownership of the smbpasswd file.
# ls -lL /var/opt/samba/private/smbpasswd

If the smbpasswd file is not owned by root, this is a finding.'
  desc 'fix', 'Use the chown command to configure the smb passwd file. 
# chown root <path>/smbpasswd'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36700r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1029'
  tag rid: 'SV-35225r1_rule'
  tag stig_id: 'GEN006160'
  tag gtitle: 'GEN006160'
  tag fix_id: 'F-32074r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
