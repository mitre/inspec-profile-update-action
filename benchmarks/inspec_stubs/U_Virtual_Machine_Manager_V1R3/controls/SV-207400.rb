control 'SV-207400' do
  title 'The VMM must terminate all sessions and network connections when nonlocal maintenance is completed.'
  desc 'If a maintenance session or connection remains open after maintenance is completed, it may be hijacked by an attacker and used to compromise or damage the system.

Some maintenance and test tools are either standalone devices with their own VMMs or are applications bundled with a VMM.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the VMM or VMM component and not communicating across a network connection.'
  desc 'check', 'Verify the VMM terminates all sessions and network connections when nonlocal maintenance is completed.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to terminate all sessions and network connections when nonlocal maintenance is completed.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7657r365610_chk'
  tag severity: 'medium'
  tag gid: 'V-207400'
  tag rid: 'SV-207400r378961_rule'
  tag stig_id: 'SRG-OS-000126-VMM-000640'
  tag gtitle: 'SRG-OS-000126'
  tag fix_id: 'F-7657r365611_fix'
  tag 'documentable'
  tag legacy: ['SV-71261', 'V-57001']
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end
