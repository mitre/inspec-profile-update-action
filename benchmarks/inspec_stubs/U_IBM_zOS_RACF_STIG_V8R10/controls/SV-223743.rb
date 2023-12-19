control 'SV-223743' do
  title 'IBM FTP.DATA configuration for the FTP server must have the INACTIVE statement properly set.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Refer to the Data configuration file specified on the SYSFTPD DD statement in the FTP started task JCL.

If the INACTIVE statement is coded with a value between 1 and 900 (seconds), this is not a finding.'
  desc 'fix', 'Configure the FTP configuration to include an Inactive statement with a value between 1 and 900 (seconds).'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25416r514917_chk'
  tag severity: 'medium'
  tag gid: 'V-223743'
  tag rid: 'SV-223743r604139_rule'
  tag stig_id: 'RACF-FT-000110'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-25404r514918_fix'
  tag 'documentable'
  tag legacy: ['V-98193', 'SV-107297']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
