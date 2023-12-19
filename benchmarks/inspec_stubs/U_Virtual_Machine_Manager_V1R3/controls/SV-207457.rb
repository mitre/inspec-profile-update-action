control 'SV-207457' do
  title 'The VMM must provide an audit reduction capability that supports after-the-fact investigations of security incidents.'
  desc 'If the audit reduction capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

Audit reduction capability must support after-the-fact investigations of security incidents either natively or through the use of third-party tools

This requirement is specific to VMMs with audit reduction capabilities'
  desc 'check', 'Verify the VMM provides an audit reduction capability that supports after-the-fact investigations of security incidents.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to provide an audit reduction capability that supports after-the-fact investigations of security incidents.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7714r365775_chk'
  tag severity: 'medium'
  tag gid: 'V-207457'
  tag rid: 'SV-207457r854628_rule'
  tag stig_id: 'SRG-OS-000349-VMM-001270'
  tag gtitle: 'SRG-OS-000349'
  tag fix_id: 'F-7714r365776_fix'
  tag 'documentable'
  tag legacy: ['SV-71375', 'V-57115']
  tag cci: ['CCI-001877']
  tag nist: ['AU-7 a']
end
