control 'SV-71509' do
  title 'The operating system must immediately notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately when storage volume reaches 75% utilization, they are unable to plan for audit record storage capacity expansion.'
  desc 'check', 'Verify the operating system immediately notifies the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to immediately notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57859r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57249'
  tag rid: 'SV-71509r1_rule'
  tag stig_id: 'SRG-OS-000343-GPOS-00134'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-62183r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
