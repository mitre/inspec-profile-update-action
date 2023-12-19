control 'SV-223835' do
  title 'The IBM z/OS PROFILE.TCPIP configuration for the TN3270 Telnet server must have the INACTIVE statement properly specified.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.'
  desc 'check', 'Refer to the Profile configuration file specified on the PROFILE DD statement in the TN3270 started task JCL.

Note: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

TELNETGLOBAL Block (only one defined)

TELNETPARMS Block (one defined for each port the server is listening to, typically ports 23 and 992)

If the TELNETPARMS INACTIVE statement is coded either in the TELNETGLOBALS or within each TELNETPARMS statement block and specifies a value between "1" and "900", this is not a finding.'
  desc 'fix', 'Configure the configuration statements in the PROFILE.Tn3270 to conform to the specifications below:

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

The TELNETPARMS INACTIVE statement is coded either within the TELNETGLOBALS OR within each TELNETPARMS statement block and specifies a value between "1" and "900".'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25508r515193_chk'
  tag severity: 'medium'
  tag gid: 'V-223835'
  tag rid: 'SV-223835r604139_rule'
  tag stig_id: 'RACF-TN-000060'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-25496r515194_fix'
  tag 'documentable'
  tag legacy: ['V-98377', 'SV-107481']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
