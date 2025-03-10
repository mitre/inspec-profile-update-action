control 'SV-16847' do
  title 'Virtual machine rollbacks are performed when virtual machine is connected to the network.'
  desc 'Virtual machines may be rolled back to a previous state. Rolling back a virtual machine can re-expose patched vulnerabilities, re-enable previously disabled accounts or passwords, remove log files of a machine, use previously retired encryption keys, and change firewalls to expose vulnerabilities. Rolling back virtual machines can also reintroduce malicious code, and protocols reusing TCP sequence numbers that had been previously removed, which could allow TCP hijacking attacks.'
  desc 'check', 'Ask the IAO/SA the process used for virtual machine rollbacks.  If no process is used that includes disconnecting the virtual machine from the network before performing a revert to snapshot or rollback, this is a finding.'
  desc 'fix', 'Disconnect from the network or power off the virtual machine before rollbacks.'
  impact 0.3
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16265r1_chk'
  tag severity: 'low'
  tag gid: 'V-15905'
  tag rid: 'SV-16847r1_rule'
  tag stig_id: 'ESX1090'
  tag gtitle: 'Virtual machine rollbacks are performed'
  tag fix_id: 'F-15866r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECSC-1'
end
