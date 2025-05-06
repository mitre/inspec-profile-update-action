control 'SV-29496' do
  title 'Installed FTP server is configured to allow access to the system drive.'
  desc 'This is a Category 1 finding because the FTP service allows remote users to access shared files and directories which could provide access to system resources and compromise the system, especially if the user can gain access to the root directory of the boot drive.'
  desc 'check', 'In the “Command Prompt” window, enter the following command, log on using an authenticated FTP account, and attempt to access the root of the boot drive:

X:\\>ftp 127.0.0.1
(Connected to ftru065103.ncr.disa.mil.
220 ftru065103 Microsoft FTP Service (Version 2.0).)

User: ftpuser
(331 Password required for ftpuser.)

Password: password
(230 User ftpuser logged in.)

ftp> dir /

If the FTP session indicates access to operating system files like “PAGEFILE.SYS” or “NTLDR,” then this is a finding.'
  desc 'fix', 'Configure the system to prevent an FTP Service from allowing access to the system drive.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-516r1_chk'
  tag severity: 'high'
  tag gid: 'V-1121'
  tag rid: 'SV-29496r1_rule'
  tag gtitle: 'FTP System File Access'
  tag fix_id: 'F-5814r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
