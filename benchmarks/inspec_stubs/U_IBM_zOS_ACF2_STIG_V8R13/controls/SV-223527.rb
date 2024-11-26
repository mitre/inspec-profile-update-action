control 'SV-223527' do
  title 'IBM z/OS FTP.DATA configuration for the FTP Server must have INACTIVE statement properly set.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Refer to the Data configuration file specified on the SYSFTPD DD statement in the FTP started task JCL.

If the INACTIVE statement is coded with a value between 1 and 900 (seconds) this is not a finding.'
  desc 'fix', 'Configure the FTP.DATA CONFIGURATION STATEMENT to include the following:

INACTIVE [A value between 1 and 900]'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25200r500715_chk'
  tag severity: 'medium'
  tag gid: 'V-223527'
  tag rid: 'SV-223527r533198_rule'
  tag stig_id: 'ACF2-FT-000110'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-25188r500716_fix'
  tag 'documentable'
  tag legacy: ['V-97759', 'SV-106863']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
