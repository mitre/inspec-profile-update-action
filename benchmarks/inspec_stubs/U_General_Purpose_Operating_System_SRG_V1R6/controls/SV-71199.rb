control 'SV-71199' do
  title 'The operating system must initiate session audits at system start-up.'
  desc 'If auditing is enabled late in the start-up process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Verify the operating system initiates session audits at system start-up. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to initiate session audits at system start-up.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57509r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56939'
  tag rid: 'SV-71199r1_rule'
  tag stig_id: 'SRG-OS-000254-GPOS-00095'
  tag gtitle: 'SRG-OS-000254-GPOS-00095'
  tag fix_id: 'F-61835r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
