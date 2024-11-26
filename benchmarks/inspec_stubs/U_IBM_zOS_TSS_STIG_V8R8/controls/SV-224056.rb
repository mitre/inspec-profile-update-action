control 'SV-224056' do
  title 'IBM z/OS PROFILE.TCPIP configuration statements for the TCP/IP stack must be properly coded.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyberattacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Refer to the Profile configuration file specified on the PROFILE DD statement in the TCPIP started task JCL.

If the following items are in effect for the configuration statements specified in the TCP/IP Profile configuration file, this is not a finding.

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

-The SMFPARMS statement is not coded or commented out.
-The DELETE statement is not coded or commented out for production systems.
-The SMFCONFIG statement is coded with (at least) the FTPCLIENT and TN3270CLIENT operands.
-The TCPCONFIG and UDPCONFIG statements are coded with (at least) the RESTRICTLOWPORTS operand.

If the TCPCONFIG does not have the TTLS statement coded, this is a finding.

NOTE: If the INCLUDE statement is coded, the data set specified will be checked for access authorization compliance.'
  desc 'fix', 'Ensure the following items are in effect for the configuration statements specified in the TCP/IP Profile configuration file:

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

-The SMFPARMS statement is not coded or commented out.
-The DELETE statement is not coded or commented out for production systems.
-The SMFCONFIG statement is coded with (at least) the FTPCLIENT and TN3270CLIENT operands.
-The TCPCONFIG and UDPCONFIG statements are coded with (at least) the RESTRICTLOWPORTS operand.

NOTE: If the INCLUDE statement is coded, the data set specified will be checked for access authorization compliance in STIG ID ITCP0070.

BASE TCP/IP PROFILE.TCPIP CONFIGURATION STATEMENTS
FUNCTIONS

INCLUDE- Specifies the name of an MVS data set that contains additional PROFILE.TCPIP statements to be used
- Alters the configuration specified by previous statements

SMFPARMS- Specifies SMF logging options for some TCP applications; replaced by SMFCONFIG
- Controls collection of audit data

DELETE- Specifies some previous statements, including PORT and PORTRANGE, that are to be deleted
- Alters the configuration specified by previous statements

SMFCONFIG- Specifies SMF logging options for Telnet, FTP, TCP, API, and stack activity
- Controls collection of audit data

TCPCONFIG- Specifies various settings for the TCP protocol layer of TCP/IP
- Controls port access   

TCPCONFIG coded with TTLS - Specifies that the AT-TLS function is activated for the TCP/IP stack. The AT-TLS function provides invocation of System SSL in the TCP transport layer of the stack. 

Note: If AT-TLS is enabled, you must activate the SERVAUTH class, define the INITSTACK resource profile, and permit users to it.

NOTE: If the INCLUDE statement is coded, the data set specified will be checked for access authorization compliance.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25729r816957_chk'
  tag severity: 'medium'
  tag gid: 'V-224056'
  tag rid: 'SV-224056r816959_rule'
  tag stig_id: 'TSS0-TC-000010'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-25717r816958_fix'
  tag 'documentable'
  tag legacy: ['V-98819', 'SV-107923']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
