control 'SV-224066' do
  title 'IBM z/OS SMF recording options for the TN3270 Telnet server must be properly specified.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyberattacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).

'
  desc 'check', 'Refer to the Profile configuration file specified on the PROFILE DD statement in the TCPIP started task JCL.

If the following configuration statement settings are in effect in the TCP/IP Profile configuration data set, this is not a finding.

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration data set, the data set specified on this statement must be checked for the following items as well.

-The TELNETPARMS SMFINIT statement is coded with the TYPE119 operand within each TELNETPARMS statement block.
-The TELNETPARMS SMFTERM statement is coded with the TYPE119 operand within each TELNETPARMS statement block.

Note: The SMFINIT and SMFTERM statement can appear in both TELNETGLOBAL and TELNETPARM statement blocks. If duplicate statements appear in the TELNETGLOBALS, TELNETPARMS, Telnet uses the last valid statement that was specified.'
  desc 'fix', 'Code TN3270 configuration file to the requirements specified below.

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

-The TELNETPARMS SMFINIT statement is coded with the TYPE119 operand within each TELNETPARMS statement block.
-The TELNETPARMS SMFTERM statement is coded with the TYPE119 operand within each TELNETPARMS statement block.

NOTE: Effective in z/OS release 1.2, the SMFINIT and SMFTERM statement can appear in both TELNETGLOBAL and TELNETPARM statement blocks.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25739r516597_chk'
  tag severity: 'medium'
  tag gid: 'V-224066'
  tag rid: 'SV-224066r877904_rule'
  tag stig_id: 'TSS0-TN-000020'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-25727r516598_fix'
  tag satisfies: ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000032-GPOS-00013']
  tag 'documentable'
  tag legacy: ['V-98839', 'SV-107943']
  tag cci: ['CCI-000067', 'CCI-002884']
  tag nist: ['AC-17 (1)', 'MA-4 (1) (a)']
end
