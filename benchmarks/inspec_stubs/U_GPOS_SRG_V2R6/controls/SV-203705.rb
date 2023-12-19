control 'SV-203705' do
  title 'The operating system must provide an audit reduction capability that supports after-the-fact investigations of security incidents.'
  desc 'If the audit reduction capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

Audit reduction capability must support after-the-fact investigations of security incidents either natively or through the use of third-party tools.

This requirement is specific to operating systems with audit reduction capabilities.'
  desc 'check', 'Verify the operating system provides an audit reduction capability that supports after-the-fact investigations of security incidents. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide an audit reduction capability that supports after-the-fact investigations of security incidents.'
  impact 0.3
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3830r375062_chk'
  tag severity: 'low'
  tag gid: 'V-203705'
  tag rid: 'SV-203705r877387_rule'
  tag stig_id: 'SRG-OS-000349-GPOS-00137'
  tag gtitle: 'SRG-OS-000349'
  tag fix_id: 'F-3830r375063_fix'
  tag 'documentable'
  tag legacy: ['V-57255', 'SV-71515']
  tag cci: ['CCI-001877']
  tag nist: ['AU-7 a']
end
