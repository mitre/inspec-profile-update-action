control 'SV-224054' do
  title 'IBM z/OS SMF recording options for the SSH daemon must be configured to write SMF records for all eligible events.'
  desc 'SMF data collection is the basic unit of tracking of all system functions and actions. Included in this tracking data are the audit trails from each of the ACPs. If the control options for the recording of this tracking are not properly maintained, then accountability cannot be monitored, and its use in the execution of a contingency plan could be compromised.

'
  desc 'check', 'Refer to the Profile configuration file specified on the PROFILE DD statement in the TCPIP started task JCL.

If the following configuration statement settings are in effect in the TCP/IP Profile configuration data set, this is not a finding.

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration data set, the data set specified on this statement must be checked for the following items as well.

-The TELNETPARMS SMFINIT statement is coded with the TYPE119 operand within each TELNETPARMS statement block.
-The TELNETPARMS SMFTERM statement is coded with the TYPE119 operand within each TELNETPARMS statement block.

Note: The SMFINIT and SMFTERM statement can appear in both TELNETGLOBAL and TELNETPARM statement blocks. If duplicate statements appear in the TELNETGLOBALS, TELNETPARMS, Telnet uses the last valid statement that was specified.'
  desc 'fix', 'Configure the TELNETPARMS SMFINIT and SMFTERM statements in the PROFILE.TCPIP file to conform to the requirements specified below.

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

-The TELNETPARMS SMFINIT statement is coded with the TYPE119 operand within each TELNETPARMS statement block.
-The TELNETPARMS SMFTERM statement is coded with the TYPE119 operand within each TELNETPARMS statement block.

Note: The SMFINIT and SMFTERM statement can appear in both TELNETGLOBAL and TELNETPARM statement blocks. If duplicate statements appear in the TELNETGLOBALS, TELNETPARMS, Telnet uses the last valid statement that was specified.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25727r516561_chk'
  tag severity: 'medium'
  tag gid: 'V-224054'
  tag rid: 'SV-224054r877892_rule'
  tag stig_id: 'TSS0-SS-000010'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-25715r516562_fix'
  tag satisfies: ['SRG-OS-000032-GPOS-00013', 'SRG-OS-000392-GPOS-00172']
  tag 'documentable'
  tag legacy: ['SV-107919', 'V-98815']
  tag cci: ['CCI-000067', 'CCI-002884']
  tag nist: ['AC-17 (1)', 'MA-4 (1) (a)']
end
