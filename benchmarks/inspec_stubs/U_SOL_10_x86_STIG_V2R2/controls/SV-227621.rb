control 'SV-227621' do
  title 'Manual page files must have mode 0655 or less permissive.'
  desc 'If manual pages are compromised, misleading information could be inserted, causing actions that may compromise the system.'
  desc 'check', 'Check the mode of the manual page files.
Procedure: 
# ls -lLR /usr/share/man /usr/sfw/share/man /usr/sfw/man

If any of the manual page files have a mode more permissive than 0655, this is a finding.'
  desc 'fix', 'Change the mode of manual page files to 0655 or less permissive.

Procedure (example):
# chmod 0655 <path>/<manpage>'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29783r488420_chk'
  tag severity: 'low'
  tag gid: 'V-227621'
  tag rid: 'SV-227621r603266_rule'
  tag stig_id: 'GEN001280'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29771r488421_fix'
  tag 'documentable'
  tag legacy: ['V-792', 'SV-39835']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
