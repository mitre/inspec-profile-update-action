control 'SV-207419' do
  title 'The VMM must initiate session audits at system startup.'
  desc 'If auditing is enabled late in the startup process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Verify the VMM initiates session audits at system startup.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to initiate session audits at system startup.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7676r365667_chk'
  tag severity: 'medium'
  tag gid: 'V-207419'
  tag rid: 'SV-207419r379231_rule'
  tag stig_id: 'SRG-OS-000254-VMM-000880'
  tag gtitle: 'SRG-OS-000254'
  tag fix_id: 'F-7676r365668_fix'
  tag 'documentable'
  tag legacy: ['V-57039', 'SV-71299']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
