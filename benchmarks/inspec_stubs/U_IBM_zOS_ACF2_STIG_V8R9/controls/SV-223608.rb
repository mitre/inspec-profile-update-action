control 'SV-223608' do
  title 'IBM z/OS PROFILE.TCPIP configuration INACTIVITY statement must be configured to 900 seconds.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific operating system functionality where the system owner, data owner, or organization requires additional assurance."
  desc 'check', 'Refer to the Profile configuration file specified on the PROFILE DD statement in the TCPIP started task JCL.

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

TELNETPARMS Block (one defined for each port the server is listening to, typically ports 23 and 992)

If the TELNETPARMS INACTIVE statement is coded within each TELNETPARMS statement block and specifies a value between 1 and 900, this is not a finding.

NOTE: Effective in z/OS release 1.2, the INACTIVE statement can appear in both TELNETGLOBAL and TELNETPARM statement blocks.'
  desc 'fix', 'Configure the PROFILE.TCPIP file as specified below:

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

TELNETPARMS Block (one defined for each port the server is listening to, typically ports 23 and 992)

The TELNETPARMS INACTIVE statement is coded within each TELNETPARMS statement block and specifies a value between 1 and 900.

INACTIVE statements should not be coded with a value greater than 900 or 0. 0 disables the inactivity timer check.

NOTE: Effective in z/OS release 1.2, the INACTIVE statement can appear in both TELNETGLOBAL and TELNETPARM statement blocks.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25281r504785_chk'
  tag severity: 'medium'
  tag gid: 'V-223608'
  tag rid: 'SV-223608r853561_rule'
  tag stig_id: 'ACF2-TN-000010'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag fix_id: 'F-25269r504786_fix'
  tag 'documentable'
  tag legacy: ['SV-107025', 'V-97921']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
