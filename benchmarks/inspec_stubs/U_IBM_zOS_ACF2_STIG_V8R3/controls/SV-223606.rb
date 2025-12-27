control 'SV-223606' do
  title 'IBM z/OS PROFILE.TCPIP configuration statement must include SMFPARMS and/or SMFCONFIG statement for each TCP/IP stack.'
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

The SMFPARMS statement is not coded or commented out.
The DELETE statement is not coded or commented out for production systems.
The SMFCONFIG statement is coded with (at least) the FTPCLIENT and TN3270CLIENT operands.
The TCPCONFIG and UDPCONFIG statements are coded with (at least) the RESTRICTLOWPORTS operand.

NOTE: If the INCLUDE statement is coded, the data set specified will be checked for access authorization compliance in STIG ID ITCP0070.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25279r504782_chk'
  tag severity: 'medium'
  tag gid: 'V-223606'
  tag rid: 'SV-223606r533198_rule'
  tag stig_id: 'ACF2-TC-000080'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-25267r504783_fix'
  tag 'documentable'
  tag legacy: ['SV-107021', 'V-97917']
  tag cci: ['CCI-002884']
  tag nist: ['MA-4 (1) (a)']
end
