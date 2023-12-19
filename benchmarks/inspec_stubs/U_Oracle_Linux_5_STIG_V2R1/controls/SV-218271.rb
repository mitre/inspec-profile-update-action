control 'SV-218271' do
  title 'Manual page files must have mode 0644 or less permissive.'
  desc 'If manual pages are compromised, misleading information could be inserted, causing actions to compromise the system.'
  desc 'check', 'Check the mode of the manual page files.

Procedure:

# find /usr/share/man /usr/share/info /usr/share/infopage  -type f -perm +022 -exec stat -c %a:%n {} \\; |> more

Note: This list only displays manual files with offending permissions.

If any of the manual page files have a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of manual page files to 0644 or less permissive.

Procedure (example):
# chmod 0644 /path/to/manpage'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19746r568717_chk'
  tag severity: 'low'
  tag gid: 'V-218271'
  tag rid: 'SV-218271r603259_rule'
  tag stig_id: 'GEN001280'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19744r568718_fix'
  tag 'documentable'
  tag legacy: ['V-792', 'SV-64517']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
