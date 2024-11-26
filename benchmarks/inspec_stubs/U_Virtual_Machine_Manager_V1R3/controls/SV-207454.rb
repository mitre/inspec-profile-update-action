control 'SV-207454' do
  title 'The VMM must provide an immediate warning to the SA and ISSO, at a minimum, when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately when storage volume reaches 75%, they are unable to plan for audit record storage capacity expansion.'
  desc 'check', 'Verify the VMM provides an immediate warning to the SA and ISSO, at a minimum, when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to provide an immediate warning to the SA and ISSO, at a minimum, when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7711r365766_chk'
  tag severity: 'medium'
  tag gid: 'V-207454'
  tag rid: 'SV-207454r854625_rule'
  tag stig_id: 'SRG-OS-000343-VMM-001240'
  tag gtitle: 'SRG-OS-000343'
  tag fix_id: 'F-7711r365767_fix'
  tag 'documentable'
  tag legacy: ['V-57109', 'SV-71369']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
