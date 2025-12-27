control 'SV-218814' do
  title 'IIS 10.0 web server system files must conform to minimum file permission requirements.'
  desc 'This check verifies the key web server system configuration files are owned by the SA or the web administrator controlled account. These same files that control the configuration of the web server, and thus its behavior, must also be accessible by the account running the web service. If these files are altered by a malicious user, the web server would no longer be under the control of its managers and owners; properties in the web server configuration could be altered to compromise the entire server platform.'
  desc 'check', 'Open Explorer and navigate to the inetpub directory.

Right-click "inetpub" and select "Properties".

Click the "Security" tab.

Verify the permissions for the following users; if the permissions are less restrictive, this is a finding.

System: Full control
Administrators: Full control
TrustedInstaller: Full control
ALL APPLICATION PACKAGES (built-in security group): Read and execute
ALL RESTRICTED APPLICATION PACKAGES (built-in security group): Read and execute
Users: Read and execute, list folder contents
CREATOR OWNER: Full Control, Subfolders and files only'
  desc 'fix', 'Open Explorer and navigate to the inetpub directory.

Right-click "inetpub" and select "Properties".

Click the "Security" tab.

Set the following permissions: 

SYSTEM: Full control
Administrators: Full control
TrustedInstaller: Full control
ALL APPLICATION PACKAGES (built-in security group): Read and execute
Users: Read and execute, list folder contents
CREATOR OWNER: special permissions to subkeys'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20286r310917_chk'
  tag severity: 'medium'
  tag gid: 'V-218814'
  tag rid: 'SV-218814r850575_rule'
  tag stig_id: 'IIST-SV-000144'
  tag gtitle: 'SRG-APP-000340-WSR-000029'
  tag fix_id: 'F-20284r310918_fix'
  tag 'documentable'
  tag legacy: ['SV-109267', 'V-100163']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
