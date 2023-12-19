control 'SV-29492' do
  title 'Installed FTP server is configured to allow prohibited logins.'
  desc 'The FTP (File Transfer Protocol) service allows remote users to access shared files and directories.  Allowing anonymous FTP makes user auditing difficult.

Using accounts that have administrator privileges to log on to FTP risks that the user id and password will be captured on the network, and give administrator access to an unauthorized user.'
  desc 'check', 'In the “Command Prompt” window, enter the following command, and attempt to logon as the user “anonymous:”

C:\\>ftp 127.0.0.1
(Connected to ftru014538.ncr.disa.mil.
220 ftru014538 Microsoft FTP Service (Version 2.0).)

User: anonymous
(331 Anonymous access allowed, send identity (e-mail name) as password.)

Password: password
(230 Anonymous user logged in.)
ftp>

If the command response indicates that an anonymous FTP login was permitted, then this is a finding.


Severity Override:  If accounts with administrator privileges are used to access FTP, then this becomes a Category I finding.'
  desc 'fix', 'Configure the system to prevent an installed FTP service from allowing prohibited logons.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-515r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1120'
  tag rid: 'SV-29492r1_rule'
  tag gtitle: 'Prohibited FTP Logins'
  tag fix_id: 'F-5813r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If accounts with administrator privileges are used to access FTP, then this becomes a Category I finding.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
