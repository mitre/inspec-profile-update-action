control 'SV-223614' do
  title 'IBM z/OS PROFILE.TCPIP configuration for the TN3270 Telnet Server must have INACTIVE statement properly specified.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Refer to the Profile configuration file specified on the PROFILE DD statement in the TCPIP started task JCL.

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

TELNETPARMS Block (one defined for each port the server is listening to, typically ports 23 and 992)

If the TELNETPARMS INACTIVE statement is coded within each TELNETPARMS statement block and specifies a value between 1 and 900, this is not a finding.

NOTE: Effective in z/OS release 1.2, the INACTIVE statement can appear in both TELNETGLOBAL and TELNETPARM statement blocks.'
  desc 'fix', 'Configure the PROFILE.TCPIP file as specified below:

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

"TELNETPARMS Block (one defined for each port the server is listening to, typically ports 23 and 992)"

The TELNETPARMS INACTIVE statement is coded within each TELNETPARMS statement block and specifies a value between 1 and 900.

INACTIVE statements should not be coded with a value greater than 900 or 0. 0 disables the inactivity timer check.

NOTE: Effective in z/OS release 1.2, the INACTIVE statement can appear in both TELNETGLOBAL and TELNETPARM statement blocks.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25287r504803_chk'
  tag severity: 'medium'
  tag gid: 'V-223614'
  tag rid: 'SV-223614r533198_rule'
  tag stig_id: 'ACF2-TN-000070'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-25275r504804_fix'
  tag 'documentable'
  tag legacy: ['V-97933', 'SV-107037']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
