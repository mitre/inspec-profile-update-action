control 'SV-207460' do
  title 'The VMM must provide a report generation capability that supports after-the-fact investigations of security incidents.'
  desc 'If the report generation capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

The report generation capability must support after-the-fact investigations of security incidents either natively or through the use of third-party tools.'
  desc 'check', 'Verify the VMM provides a report generation capability that supports after-the-fact investigations of security incidents.

If it does not, this is a finding.'
  desc 'fix', 'Ensure the VMM provides a report generation capability that supports after-the-fact investigations of security incidents.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7717r365784_chk'
  tag severity: 'medium'
  tag gid: 'V-207460'
  tag rid: 'SV-207460r854631_rule'
  tag stig_id: 'SRG-OS-000352-VMM-001300'
  tag gtitle: 'SRG-OS-000352'
  tag fix_id: 'F-7717r365785_fix'
  tag 'documentable'
  tag legacy: ['V-57121', 'SV-71381']
  tag cci: ['CCI-001880']
  tag nist: ['AU-7 a']
end
