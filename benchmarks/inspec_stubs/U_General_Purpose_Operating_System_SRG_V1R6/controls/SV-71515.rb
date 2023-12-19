control 'SV-71515' do
  title 'The operating system must provide an audit reduction capability that supports after-the-fact investigations of security incidents.'
  desc 'If the audit reduction capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

Audit reduction capability must support after-the-fact investigations of security incidents either natively or through the use of third-party tools.

This requirement is specific to operating systems with audit reduction capabilities.'
  desc 'check', 'Verify the operating system provides an audit reduction capability that supports after-the-fact investigations of security incidents. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide an audit reduction capability that supports after-the-fact investigations of security incidents.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57865r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57255'
  tag rid: 'SV-71515r1_rule'
  tag stig_id: 'SRG-OS-000349-GPOS-00137'
  tag gtitle: 'SRG-OS-000349-GPOS-00137'
  tag fix_id: 'F-62189r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001877']
  tag nist: ['AU-7 a']
end
