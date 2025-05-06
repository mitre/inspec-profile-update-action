control 'SV-792' do
  title 'Manual page files must have mode 0644 or less permissive.'
  desc 'If manual pages are compromised, misleading information could be inserted, causing actions that may compromise the system.'
  desc 'check', 'Check the mode of the manual page files.

Procedure:
# ls -lLR /usr/share/man /usr/share/info /usr/share/infopage

If any of the manual page files have a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of manual page files to 0644 or less permissive.

Procedure (example):
# chmod 0644 <path>/<manpage>'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-295r2_chk'
  tag severity: 'low'
  tag gid: 'V-792'
  tag rid: 'SV-792r2_rule'
  tag stig_id: 'GEN001280'
  tag gtitle: 'GEN001280'
  tag fix_id: 'F-946r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
