control 'SV-71089' do
  title 'The operating system must terminate all sessions and network connections related to nonlocal maintenance when nonlocal maintenance is completed.'
  desc 'If a maintenance session or connection remains open after maintenance is completed, it may be hijacked by an attacker and used to compromise or damage the system.

Some maintenance and test tools are either standalone devices with their own operating systems or are applications bundled with an operating system.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.'
  desc 'check', 'Verify the operating system terminates all sessions and network connections related to nonlocal maintenance when nonlocal maintenance is completed. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to terminate all sessions and network connections related to nonlocal maintenance when nonlocal maintenance is completed.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57399r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56829'
  tag rid: 'SV-71089r1_rule'
  tag stig_id: 'SRG-OS-000126-GPOS-00066'
  tag gtitle: 'SRG-OS-000126-GPOS-00066'
  tag fix_id: 'F-61725r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end
