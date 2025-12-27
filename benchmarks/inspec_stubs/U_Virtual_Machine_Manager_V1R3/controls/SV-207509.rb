control 'SV-207509' do
  title 'The VMM must generate audit records when successful/unsuccessful attempts to access security objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records when successful/unsuccessful attempts to access security objects occur.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records when successful/unsuccessful attempts to access security objects occur.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7766r365931_chk'
  tag severity: 'medium'
  tag gid: 'V-207509'
  tag rid: 'SV-207509r380329_rule'
  tag stig_id: 'SRG-OS-000458-VMM-001810'
  tag gtitle: 'SRG-OS-000458'
  tag fix_id: 'F-7766r365932_fix'
  tag 'documentable'
  tag legacy: ['SV-71579', 'V-57319']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
