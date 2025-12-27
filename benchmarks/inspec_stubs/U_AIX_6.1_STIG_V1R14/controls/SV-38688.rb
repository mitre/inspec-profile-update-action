control 'SV-38688' do
  title 'All manual page files must not have extended ACLs.'
  desc 'If manual pages are compromised, misleading information could be inserted, causing actions that may compromise the system.'
  desc 'check', 'Determine if any manual page files on the system have extended ACLs.

Check to see if extended permissions are disabled.
#aclget < directory >/< file >  

If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACLs from system manual page file(s) and disable extended permissions.

#acledit < directory >/< file >'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36961r1_chk'
  tag severity: 'low'
  tag gid: 'V-22316'
  tag rid: 'SV-38688r1_rule'
  tag stig_id: 'GEN001290'
  tag gtitle: 'GEN001290'
  tag fix_id: 'F-32226r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
