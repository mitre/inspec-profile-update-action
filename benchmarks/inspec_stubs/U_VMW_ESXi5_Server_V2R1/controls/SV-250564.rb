control 'SV-250564' do
  title 'Access to the management network must be strictly controlled through a network gateway.'
  desc 'A controlled gateway or other controlled method must be configured to access the management network. The management network must be isolated in order to prevent access by internal and external, unauthorized personnel.'
  desc 'check', 'Ask the SA if a controlled gateway or other controlled access method to the management network has been implemented and documented. Ask to see the documentation. Note that this check refers to an entity outside the scope of the ESXi server system.

If a controlled gateway or other controlled access method has not been implemented or documented, this is a finding.'
  desc 'fix', 'Implement and document a controlled gateway or other controlled access method to the management network. Note that this check refers to an entity outside the scope of the ESXi server system.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53999r798689_chk'
  tag severity: 'medium'
  tag gid: 'V-250564'
  tag rid: 'SV-250564r798691_rule'
  tag stig_id: 'ESXI5-VMNET-000023'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53953r798690_fix'
  tag 'documentable'
  tag legacy: ['SV-51258', 'V-39400']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
