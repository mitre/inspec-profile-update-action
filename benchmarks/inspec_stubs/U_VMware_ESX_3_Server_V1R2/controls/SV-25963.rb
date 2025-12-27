control 'SV-25963' do
  title 'All manual page files must not have extended ACLs.'
  desc 'If manual pages are compromised, misleading information could be inserted, causing actions that may compromise the system.'
  desc 'check', 'Determine if any manual page files on the system have extended ACLs.  If so, this is a finding.'
  desc 'fix', 'Remove the extended ACLs from system manual page file(s).'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29104r1_chk'
  tag severity: 'low'
  tag gid: 'V-22316'
  tag rid: 'SV-25963r1_rule'
  tag stig_id: 'GEN001290'
  tag gtitle: 'GEN001290'
  tag fix_id: 'F-26107r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
