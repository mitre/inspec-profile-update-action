control 'SV-253847' do
  title 'All installation files originally downloaded to the Tanium Server must be configured to download to a location other than the Tanium Server directory.'
  desc %q(Typically, the Tanium Server stores the Package Source Files that it downloads from the internet and server shares or files uploaded through the Tanium Console in a subdirectory of the server's installation directory called "Downloads". To ensure package files are not accessible to nonauthorized functions, the files must be relocated to outside of the server's installation directory.)
  desc 'check', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Run regedit as Administrator.

4. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> WOW6432Node >> Tanium >> Tanium Server. 

5. Validate the value name "DownloadPath" with value type "REG_SZ" does not point to a location within the Tanium Server directory.

If the value name "DownloadPath" with value type "REG_SZ" does not exist or points to a location within the Tanium Server directory, this is a finding.

If the "DownloadPath REG_SZ" value points to a location within the Tanium Server directory, this is a finding.'
  desc 'fix', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Create a new folder outside of the Tanium Server directory (e.g., E:\\Stage\\Downloads).

4. Run regedit as Administrator.

5. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> WOW6432Node >> Tanium >> Tanium Server.

6. Add or change the value name "DownloadPath" with value type "REG_SZ" to point to the location of the relocated installation package files (e.g., E:\\Stage\\Downloads).

7. Move the files from the original directory (E:\\Program Files\\Tanium\\Tanium Server\\Downloads) to the location created for the installation package files.

8. Move the files from the original directory (E:\\Program Files\\Tanium\\Tanium Server\\Downloads) to the location created for the installation package files.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57299r842567_chk'
  tag severity: 'medium'
  tag gid: 'V-253847'
  tag rid: 'SV-253847r842569_rule'
  tag stig_id: 'TANS-SV-000016'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-57250r842568_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
