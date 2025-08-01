control 'SV-207515' do
  title 'The VMM must generate audit records when successful/unsuccessful attempts to delete privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records when successful/unsuccessful attempts to delete privileges occur.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records when successful/unsuccessful attempts to delete privileges occur.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7772r365949_chk'
  tag severity: 'medium'
  tag gid: 'V-207515'
  tag rid: 'SV-207515r381460_rule'
  tag stig_id: 'SRG-OS-000466-VMM-001870'
  tag gtitle: 'SRG-OS-000466'
  tag fix_id: 'F-7772r365950_fix'
  tag 'documentable'
  tag legacy: ['V-57331', 'SV-71591']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
