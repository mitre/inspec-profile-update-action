control 'SV-203708' do
  title 'The operating system must provide a report generation capability that supports after-the-fact investigations of security incidents.'
  desc 'If the report generation capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

The report generation capability must support after-the-fact investigations of security incidents either natively or through the use of third-party tools.'
  desc 'check', 'Verify the operating system provides a report generation capability that supports after-the-fact investigations of security incidents. If it does not, this is a finding.'
  desc 'fix', 'Ensure the operating system provides a report generation capability that supports after-the-fact investigations of security incidents.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3833r375071_chk'
  tag severity: 'medium'
  tag gid: 'V-203708'
  tag rid: 'SV-203708r379723_rule'
  tag stig_id: 'SRG-OS-000352-GPOS-00140'
  tag gtitle: 'SRG-OS-000352'
  tag fix_id: 'F-3833r375072_fix'
  tag 'documentable'
  tag legacy: ['V-57261', 'SV-71521']
  tag cci: ['CCI-001880']
  tag nist: ['AU-7 a']
end
