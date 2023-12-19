control 'SV-37883' do
  title 'The smbpasswd file must have mode 0600 or less permissive.'
  desc 'If the smbpasswd file has a mode more permissive than 0600, it may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check the mode of files maintained using smbpasswd.
# ls -lL /var/opt/samba/private/smbpasswd

If the smbpasswd file is more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the smbpasswd file to 0600.
# chmod 0600 <path>/smbpasswd'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-37108r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1059'
  tag rid: 'SV-37883r1_rule'
  tag stig_id: 'GEN006200'
  tag gtitle: 'GEN006200'
  tag fix_id: 'F-32376r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
