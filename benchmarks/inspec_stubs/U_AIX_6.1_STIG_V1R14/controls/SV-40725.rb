control 'SV-40725' do
  title 'The /var/private/smbpasswd file must have mode 0600 or less permissive.'
  desc 'If the smbpasswd file has a mode more permissive than 0600, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check smbpasswd mode.

Procedure:
# ls -lL /var/private/smbpasswd

If smbpasswd has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the smbpasswd file to 0600.

Procedure:
# chmod 0600 /var/private/smbpasswd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39458r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1059'
  tag rid: 'SV-40725r1_rule'
  tag stig_id: 'GEN006200'
  tag gtitle: 'GEN006200'
  tag fix_id: 'F-34585r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
