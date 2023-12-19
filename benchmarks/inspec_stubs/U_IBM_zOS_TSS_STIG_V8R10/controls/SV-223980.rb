control 'SV-223980' do
  title 'IBM z/OS FTP.DATA configuration for the FTP server must have the INACTIVE statement properly set.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.'
  desc 'check', 'Refer to the file specified on the SYSFTPD DD statement in the FTP started task JCL.

If the INACTIVE statement is coded with a value greater than "600", this is a finding.

If the INACTIVE statement is coded with a value of "0", this is a finding.

If there is no INACTIVE statement coded or the INACTIVE statement is commented out, this is a finding.'
  desc 'fix', 'Code the FTPD configuration file to include the INACTIVE statement with a value between "1" and "600".'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25653r516339_chk'
  tag severity: 'medium'
  tag gid: 'V-223980'
  tag rid: 'SV-223980r877821_rule'
  tag stig_id: 'TSS0-FT-000080'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-25641r516340_fix'
  tag 'documentable'
  tag legacy: ['SV-107771', 'V-98667']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
