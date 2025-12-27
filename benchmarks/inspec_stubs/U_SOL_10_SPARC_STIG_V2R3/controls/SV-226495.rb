control 'SV-226495' do
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
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28656r482870_chk'
  tag severity: 'low'
  tag gid: 'V-226495'
  tag rid: 'SV-226495r854408_rule'
  tag stig_id: 'GEN001280'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-28644r482871_fix'
  tag 'documentable'
  tag legacy: ['SV-39835', 'V-792']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
