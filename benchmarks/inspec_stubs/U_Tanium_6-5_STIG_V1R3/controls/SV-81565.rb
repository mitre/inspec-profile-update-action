control 'SV-81565' do
  title 'All installation files originally downloaded to the Tanium Server must be configured to download to a location other than the Tanium Server directory.'
  desc "Typically, the Tanium Server stores the Package Source Files that it downloads from the Internet and server shares or files uploaded through the Tanium Console in a subdirectory of the server's installation directory called Downloads. To ensure package files are not accessible to non-authorized functions, the files must be re-located to outside of the server's installation directory."
  desc 'check', 'Access the Tanium Server interactively. 

Log on with an account with administrative privileges to the server.

Run regedit as Administrator.

Navigate to HKLM\\Software\\Wow6432Node\\Tanium\\Tanium Server.

Validate the DownloadPath REG_SZ value does not point to a location off of the Tanium Server directory. 

If the DownloadPath REG_SZ value points to a location off of the Tanium Server directory, this is a finding.'
  desc 'fix', 'Access the Tanium Server interactively. 

Log on with an account with administrative privileges to the server.

Configure a directory elsewhere on the server to relocate the installation package files.

Run regedit as Administrator.

Navigate to HKLM\\Software\\Wow6432Node\\Tanium\\Tanium Server.

Change the DownloadPath REG_SZ value to point to the location of the relocated installation package files.

Move the files from the original directory to the location created for the installation package files.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67711r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67075'
  tag rid: 'SV-81565r1_rule'
  tag stig_id: 'TANS-SV-000016'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-73175r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
