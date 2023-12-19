control 'SV-223759' do
  title 'IBM z/OS SMF recording options for the TN3270 Telnet Server must be properly specified.'
  desc 'The TN3270 Telnet Server can provide audit data in the form of SMF records. The SMF data produced provides information about individual sessions. This data includes the VTAM application, the remote and local IP addresses, and the remote and local IP port numbers. Failure to collect and retain audit data may contribute to the loss of accountability and hamper security audit activities.

'
  desc 'check', 'Refer to the Profile configuration file specified on the PROFILE DD statement in the TCPIP started task JCL.

If the following configuration statement settings are in effect in the TCP/IP Profile configuration data set, this is not a finding.

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration data set, the data set specified on this statement must be checked for the following items as well.

The TELNETPARMS SMFINIT statement is coded with the TYPE119 operand within each TELNETPARMS statement block.

The TELNETPARMS SMFTERM statement is coded with the TYPE119 operand within each TELNETPARMS statement block.

Note: The SMFINIT and SMFTERM statement can appear in both TELNETGLOBAL and TELNETPARM statement blocks. If duplicate statements appear in the TELNETGLOBALS, TELNETPARMS, Telnet uses the last valid statement that was specified.'
  desc 'fix', 'Configure the TELNETPARMS SMFINIT and SMFTERM statements in the PROFILE.TCPIP file to conform to the requirements specified below.

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

The TELNETPARMS SMFINIT statement is coded with the TYPE119 operand within each TELNETPARMS statement block.

The TELNETPARMS SMFTERM statement is coded with the TYPE119 operand within each TELNETPARMS statement block.

Note: The SMFINIT and SMFTERM statement can appear in both TELNETGLOBAL and TELNETPARM statement blocks. If duplicate statements appear in the TELNETGLOBALS, TELNETPARMS, Telnet uses the last valid statement that was specified.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25432r514965_chk'
  tag severity: 'medium'
  tag gid: 'V-223759'
  tag rid: 'SV-223759r604139_rule'
  tag stig_id: 'RACF-OS-000030'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-25420r514966_fix'
  tag satisfies: ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000032-GPOS-00013']
  tag 'documentable'
  tag legacy: ['SV-107329', 'V-98225']
  tag cci: ['CCI-000067', 'CCI-002884']
  tag nist: ['AC-17 (1)', 'MA-4 (1) (a)']
end
