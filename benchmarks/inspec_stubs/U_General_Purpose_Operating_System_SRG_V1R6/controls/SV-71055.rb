control 'SV-71055' do
  title 'The operating system must audit all activities performed during nonlocal maintenance and diagnostic sessions.'
  desc 'If events associated with nonlocal administrative access or diagnostic sessions are not logged, a major tool for assessing and investigating attacks would not be available.

This requirement addresses auditing-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system, for example, the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch.'
  desc 'check', 'Verify the operating system audits all activities performed during nonlocal maintenance and diagnostic sessions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to audit all activities performed during nonlocal maintenance and diagnostic sessions.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57365r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56795'
  tag rid: 'SV-71055r1_rule'
  tag stig_id: 'SRG-OS-000392-GPOS-00172'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-61691r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002884']
  tag nist: ['MA-4 (1) (a)']
end
