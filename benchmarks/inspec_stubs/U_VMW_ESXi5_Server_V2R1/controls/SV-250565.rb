control 'SV-250565' do
  title 'Access to the management network must be strictly controlled through a network jump box.'
  desc "Based upon an organization's risk assessment, jump boxes that run vSphere Client and other management clients (e.g., VSphere Management Assistant) must be configured. The management network must be isolated in order to prevent access by internal and external, unauthorized personnel."
  desc 'check', 'Ask the SA if a management network jump box has been implemented and documented. Ask to see the documentation. Note that this check refers to an entity outside the scope of the ESXi server system.

If a management network jump box has not been implemented or documented, this is a finding.'
  desc 'fix', 'Implement and document a management network jump box solution. 
Note that this check refers to an entity outside the scope of the ESXi server system.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54000r798692_chk'
  tag severity: 'medium'
  tag gid: 'V-250565'
  tag rid: 'SV-250565r798694_rule'
  tag stig_id: 'ESXI5-VMNET-000024'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53954r798693_fix'
  tag 'documentable'
  tag legacy: ['V-39401', 'SV-51259']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
