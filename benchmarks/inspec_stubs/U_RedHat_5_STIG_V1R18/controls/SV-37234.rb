control 'SV-37234' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35923r3_chk'
  tag severity: 'low'
  tag gid: 'V-792'
  tag rid: 'SV-37234r3_rule'
  tag stig_id: 'GEN001280'
  tag gtitle: 'GEN001280'
  tag fix_id: 'F-31181r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
