control 'SV-224064' do
  title 'The IBM z/OS PROFILE.TCPIP configuration statement must include SMFPARMS and/or SMFCONFIG Statement for each TCP/IP stack.'
  desc 'If events associated with nonlocal administrative access or diagnostic sessions are not logged, a major tool for assessing and investigating attacks would not be available.

This requirement addresses auditing-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system, for example, the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch.'
  desc 'check', 'Refer to the Profile configuration file specified on the PROFILE DD statement in the TCPIP started task JCL.

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

If the SMFPARMS statement is not coded or commented out, this is not a finding.

If the DELETE statement is not coded or commented out for production system, this is not a finding.

If the SMFCONFIG statement is coded with (at least) the FTPCLIENT and TN3270CLIENT operands, this is not a finding.

If the TCPCONFIG and UDPCONFIG statements are coded with (at least) the RESTRICTLOWPORTS operand, this is not a finding.'
  desc 'fix', 'Configure the statements in the PROFILE.TCPIP file to conform to the specifications below:

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

1) The SMFPARMS statement is not coded or commented out.
2) The DELETE statement is not coded or commented out for production systems.
3) The SMFCONFIG statement is coded with (at least) the FTPCLIENT and TN3270CLIENT operands.
4) The TCPCONFIG and UDPCONFIG statements are coded with (at least) the RESTRICTLOWPORTS operand.

NOTE: If the INCLUDE statement is coded, the data set specified will be checked for access authorization compliance in STIG ID ITCP0070.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25737r516591_chk'
  tag severity: 'medium'
  tag gid: 'V-224064'
  tag rid: 'SV-224064r561402_rule'
  tag stig_id: 'TSS0-TC-000090'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-25725r516592_fix'
  tag 'documentable'
  tag legacy: ['SV-107939', 'V-98835']
  tag cci: ['CCI-002884']
  tag nist: ['MA-4 (1) (a)']
end
