control 'SV-224069' do
  title 'IBM z/OS PROFILE.TCPIP configuration for the TN3270 Telnet server must have the INACTIVE statement properly specified.'
  desc 'Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

'
  desc 'check', 'Refer to the Profile configuration file specified on the PROFILE DD statement in the TCPIP started task JCL.

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

TELNETPARMS Block (one defined for each port the server is listening to, typically ports 23 and 992)

If the TELNETPARMS INACTIVE statement is coded within each TELNETPARMS statement block and specifies a value between "1" and "900", this is not a finding.

NOTE: Effective in z/OS release 1.2, the INACTIVE statement can appear in both TELNETGLOBAL and TELNETPARM statement blocks.'
  desc 'fix', 'Configure the configuration statements in the PROFILE.Tn3270 to conform to the specifications below:

NOTE: If the INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

The TELNETPARMS INACTIVE statement is coded either within the TELNETGLOBALS or within each TELNETPARMS statement block and specifies a value between "1" and "900".'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25742r516606_chk'
  tag severity: 'medium'
  tag gid: 'V-224069'
  tag rid: 'SV-224069r877907_rule'
  tag stig_id: 'TSS0-TN-000050'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-25730r516607_fix'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000279-GPOS-00109']
  tag 'documentable'
  tag legacy: ['V-98845', 'SV-107949']
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
