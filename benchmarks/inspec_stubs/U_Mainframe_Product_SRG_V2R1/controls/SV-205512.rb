control 'SV-205512' do
  title 'The Mainframe Product must terminate all sessions and network connections when nonlocal maintenance is completed.'
  desc 'If a maintenance session or connection remains open after maintenance is completed, it may be hijacked by an attacker and used to compromise or damage the system.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. 

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).'
  desc 'check', 'If the Mainframe Product has no function or capability for nonlocal maintenance this is not applicable.

Examine installation and configuration settings.

If the Mainframe Product does not terminate all sessions and network connections when nonlocal maintenance is completed, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to terminate all sessions and network connections when nonlocal maintenance is completed.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5778r299769_chk'
  tag severity: 'medium'
  tag gid: 'V-205512'
  tag rid: 'SV-205512r397621_rule'
  tag stig_id: 'SRG-APP-000186-MFP-000264'
  tag gtitle: 'SRG-APP-000186'
  tag fix_id: 'F-5778r299770_fix'
  tag 'documentable'
  tag legacy: ['SV-82919', 'V-68429']
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end
