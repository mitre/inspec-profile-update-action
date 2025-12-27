control 'SV-207368' do
  title 'The VMM must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the VMM (e.g., guest VM, module, or policy filter).'
  desc 'check', 'Verify the VMM generates audit records when successful/unsuccessful attempts to access privileges occur.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records when successful/unsuccessful attempts to access privileges occur.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7625r365514_chk'
  tag severity: 'medium'
  tag gid: 'V-207368'
  tag rid: 'SV-207368r378727_rule'
  tag stig_id: 'SRG-OS-000064-VMM-000320'
  tag gtitle: 'SRG-OS-000064'
  tag fix_id: 'F-7625r365515_fix'
  tag 'documentable'
  tag legacy: ['SV-71183', 'V-56923']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
