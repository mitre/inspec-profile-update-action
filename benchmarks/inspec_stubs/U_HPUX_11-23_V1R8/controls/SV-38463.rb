control 'SV-38463' do
  title 'Manual page files must have mode 0644 or less permissive.'
  desc 'If manual pages are compromised, misleading information could be inserted, causing actions possibly compromising the system.'
  desc 'check', %q(Check the mode of the manual page files.
# find `env | grep MANPATH | cut -f 2,2 -d "=" | tr ':' ' ' ` -type f  \( -perm -100 -o -perm -030 -o -perm -003 \\) -exec ls -al {} +

If any manual page file mode is more permissive than 0644, this is a finding.)
  desc 'fix', 'Change the mode of manual page files to 0644 or less permissive.

Example:
# chmod 0644 <path>/<manpage>'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-39552r3_chk'
  tag severity: 'low'
  tag gid: 'V-792'
  tag rid: 'SV-38463r2_rule'
  tag stig_id: 'GEN001280'
  tag gtitle: 'GEN001280'
  tag fix_id: 'F-31561r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
