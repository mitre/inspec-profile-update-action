control 'SV-227931' do
  title 'The smbpasswd file must have mode 0600 or less permissive.'
  desc 'If the smbpasswd file has a mode more permissive than 0600, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check smbpasswd mode.

Procedure:
# ls -lL /etc/sfw/private/smbpasswd 

If smbpasswd has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the smbpasswd file to 0600.

Procedure:
# chmod 0600 /etc/sfw/private/smbpasswd'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30093r490213_chk'
  tag severity: 'medium'
  tag gid: 'V-227931'
  tag rid: 'SV-227931r603266_rule'
  tag stig_id: 'GEN006200'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-30081r490214_fix'
  tag 'documentable'
  tag legacy: ['V-1059', 'SV-40289']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
