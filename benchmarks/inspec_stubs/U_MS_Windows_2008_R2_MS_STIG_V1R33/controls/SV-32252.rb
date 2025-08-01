control 'SV-32252' do
  title 'File Transfer Protocol (FTP) servers must be configured to prevent access to the system drive.'
  desc 'The FTP service allows remote users to access shared files and directories.  Access outside of the specific directories of shared data could provide access to system resources and compromise the system.'
  desc 'check', 'If FTP is not installed on the system, this is NA.

Determine the IP address and port number assigned to FTP sites from documentation or configuration.

If Microsoft FTP is used, open "Internet Information Services (IIS) Manager".

Select "Sites" under the server name.

For any sites that reference FTP, view the Binding information for IP address and port.  The standard port for FTP is 21, however this may be changed.

Open a "Command Prompt".

Access the FTP site and review accessible directories with the following commands:

Note: Returned results may vary depending on the FTP server software.

C:\\> "ftp"
ftp> "Open IP Address Port"
(Substituting [IP Address] and [Port] with the information previously identified.  If no IP Address was listed in the Binding, attempt using "localhost".)
(Connected to IP Address
220 Microsoft FTP Service)

User (IP Address): "FTP User"
(Substituting [FTP User] with an account identified that is allowed access.  If it was determined that anonymous access was allowed to the site [see V-1120], also review access using "anonymous".)
 (331 Password required)

Password: "Password"
(Substituting [Password] with password for the account attempting access.)
(230 User ftpuser logged in.)

ftp> "Dir"

If the FTP session indicates access to areas of the system other than the specific folder for FTP data, such as the root of the drive, Program Files or Windows directories, this is a finding.'
  desc 'fix', 'Configure the system to only allow FTP access to specific folders containing the data to be available through the service.'
  impact 0.7
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-74339r2_chk'
  tag severity: 'high'
  tag gid: 'V-1121'
  tag rid: 'SV-32252r2_rule'
  tag gtitle: 'FTP System File Access'
  tag fix_id: 'F-81011r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
