control 'SV-223799' do
  title 'IBM z/OS system administrator must develop a procedure to remove or disable emergency accounts after the crisis is resolved or 72 hours.'
  desc 'IBM z/OS system administrator must develop a procedure to remove or disable emergency accounts after the crisis is resolved or 72 hours.'
  desc 'check', 'Ask the system administrator for the procedure to automatically remove or disable emergency accounts after the crisis is resolved or 72 hours.

If there is no procedure, this is a finding.'
  desc 'fix', 'Develop a procedure to remove or disable emergency user accounts after the crisis is resolved or 72 hours.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25472r515085_chk'
  tag severity: 'medium'
  tag gid: 'V-223799'
  tag rid: 'SV-223799r604139_rule'
  tag stig_id: 'RACF-OS-000450'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag fix_id: 'F-25460r515086_fix'
  tag 'documentable'
  tag legacy: ['SV-107409', 'V-98305']
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
