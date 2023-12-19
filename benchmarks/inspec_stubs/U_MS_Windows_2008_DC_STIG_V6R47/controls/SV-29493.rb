control 'SV-29493' do
  title 'File Transfer Protocol (FTP) servers must be configured to prevent anonymous logons.'
  desc 'The FTP service allows remote users to access shared files and directories. Allowing anonymous FTP makes user auditing difficult.

Using accounts that have administrator privileges to log on to FTP risks that the user id and password will be captured on the network, and give administrator access to an unauthorized user.'
  desc 'check', 'If FTP is not installed on the system, this is NA.

Determine the IP address and port number assigned to FTP sites from documentation or configuration.

If Microsoft FTP is used, open "Internet Information Services (IIS) 6.0 Manager".

Select "FTP Sites" under the server name.

View the IP address and port information for any sites listed.  The standard port for FTP is 21, however this may be changed.

Open a "Command Prompt".

Attempt to log on as the user "anonymous" with the following commands:

Note: Returned results may vary depending on the FTP server software.

C:\\> "ftp"
ftp> "Open IP Address Port"
(Substituting [IP Address] and [Port] with the information previously identified.  If no IP Address was listed in the Binding, attempt using "localhost".)
(Connected to IP Address
220 Microsoft FTP Service)

User (IP Address): "anonymous"
(331 Anonymous access allowed, send identity (e-mail name) as password.)

Password: "password"
(230 User logged in.)
ftp>

If the response indicates that an anonymous FTP login was permitted, this is a finding.

If accounts with administrator privileges are used to access FTP, this is a CAT I finding.'
  desc 'fix', 'Configure the FTP service to prevent anonymous logons.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-74325r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1120'
  tag rid: 'SV-29493r2_rule'
  tag gtitle: 'Prohibited FTP Logins'
  tag fix_id: 'F-80995r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
