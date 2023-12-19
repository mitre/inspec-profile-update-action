control 'SV-223870' do
  title 'IBM z/OS VTAM USSTAB definitions must not be used for unsecured terminals.'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.'
  desc 'check', 'Ask the system administrator to supply the following information:

- Documentation regarding terminal naming standards.
- Documentation of all procedures controlling terminal logons to the system.
- A complete list of all USS commands used by terminal users to log on to the system.
- Members and data set names containing USSTAB and LOGAPPL definitions of all terminals that can log on to the system (e.g., SYS1.VTAMLST).
- Members and data set names containing logon mode parameters.

If USSTAB definitions are only used for secure terminals (e.g., terminals that are locally attached to the host or connected to the host via secure leased lines), this is not a finding.

If USSTAB definitions are used for any unsecured terminals (e.g., dial up terminals or terminals attached to the Internet such as TN3270 or KNET 3270 emulation), this is a finding.'
  desc 'fix', 'Configure USSTAB definitions to be only used for secure terminals.

Only terminals that are locally attached to the host or connected to the host via secure leased lines located in a secured area. Only authorized personnel may enter the area where secure terminals are located. 

USSTAB or LOGAPPL definitions are used to control logon from secure terminals. These terminals can log on directly to any VTAM application (e.g., TSO, CICS, etc.) of their choice and bypass Session Manager services. Secure terminals are usually locally attached to the host or connected to the host via a private LAN without access to an external network. Only authorized personnel may enter the area where secure terminals are located.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25543r515298_chk'
  tag severity: 'medium'
  tag gid: 'V-223870'
  tag rid: 'SV-223870r604139_rule'
  tag stig_id: 'RACF-VT-000020'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-25531r515299_fix'
  tag 'documentable'
  tag legacy: ['V-98447', 'SV-107551']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
