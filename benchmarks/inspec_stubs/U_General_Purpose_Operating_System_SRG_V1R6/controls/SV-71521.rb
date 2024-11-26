control 'SV-71521' do
  title 'The operating system must provide a report generation capability that supports after-the-fact investigations of security incidents.'
  desc 'If the report generation capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

The report generation capability must support after-the-fact investigations of security incidents either natively or through the use of third-party tools.'
  desc 'check', 'Verify the operating system provides a report generation capability that supports after-the-fact investigations of security incidents. If it does not, this is a finding.'
  desc 'fix', 'Ensure the operating system provides a report generation capability that supports after-the-fact investigations of security incidents.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57871r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57261'
  tag rid: 'SV-71521r1_rule'
  tag stig_id: 'SRG-OS-000352-GPOS-00140'
  tag gtitle: 'SRG-OS-000352-GPOS-00140'
  tag fix_id: 'F-62195r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001880']
  tag nist: ['AU-7 a']
end
