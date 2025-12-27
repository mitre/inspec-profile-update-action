control 'SV-214463' do
  title 'The IIS 8.5 website document directory must be in a separate partition from the IIS 8.5 websites system files.'
  desc 'The web document (home) directory is accessed by multiple anonymous users when the web server is in production. By locating the web document (home) directory on the same partition as the web server system file the risk for unauthorized access to these protected files is increased. Additionally, having the web document (home) directory path on the same drive as the system folders also increases the potential for a drive space exhaustion attack.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click the site name under review.

Click the "Advanced Settings" from the "Actions" pane.

Review the Physical Path.

If the Path is on the same partition as the OS, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click the site name under review.

Click the “Advanced Settings” from the "Actions" pane.

Change the Physical Path to the new partition and directory location.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15672r310593_chk'
  tag severity: 'medium'
  tag gid: 'V-214463'
  tag rid: 'SV-214463r879643_rule'
  tag stig_id: 'IISW-SI-000224'
  tag gtitle: 'SRG-APP-000233-WSR-000146'
  tag fix_id: 'F-15670r310594_fix'
  tag 'documentable'
  tag legacy: ['SV-91511', 'V-76815']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
