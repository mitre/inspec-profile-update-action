control 'SV-223599' do
  title 'IBM z/OS PROFILE.TCPIP configuration statements for the TCP/IP stack must be coded properly.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Refer to the Profile configuration file specified on the PROFILE DD statement in the TCPIP started task JCL.

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

If the SMFPARMS statement is not coded or commented out, this is not a finding.

If the DELETE statement is not coded or commented out for production system, this is not a finding.

If the SMFCONFIG statement is coded with (at least) the FTPCLIENT and TN3270CLIENT operands, this is not a finding.

If the TCPCONFIG and UDPCONFIG statements are coded with (at least) the RESTRICTLOWPORTS operand, this is not a finding.

If the TCPCONFIG does not have the TTLS statement coded, this is a finding.

NOTE: If the INCLUDE statement is coded, the data set specified will be checked for access authorization compliance.'
  desc 'fix', 'Configure the statements in the PROFILE.TCPIP file to conform to the specifications below:

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

The SMFPARMS statement is not coded or commented out.
The DELETE statement is not coded or commented out for production systems.
The SMFCONFIG statement is coded with (at least) the FTPCLIENT and TN3270CLIENT operands.
The TCPCONFIG and UDPCONFIG statements are coded with (at least) the RESTRICTLOWPORTS operand.

TCPCONFIG coded with TTLS – Specifies that the AT-TLS function is activated for the TCP/IP stack. The AT-TLS function provides invocation of System SSL in the TCP transport layer of the stack. 

Note: If AT-TLS is enabled, you must activate the SERVAUTH class, define the INITSTACK resource profile, and permit users to it.

NOTE: If the INCLUDE statement is coded, the data set specified will be checked for access authorization compliance.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25272r816943_chk'
  tag severity: 'medium'
  tag gid: 'V-223599'
  tag rid: 'SV-223599r816945_rule'
  tag stig_id: 'ACF2-TC-000010'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-25260r816944_fix'
  tag 'documentable'
  tag legacy: ['V-97903', 'SV-107007']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
