control 'SV-218752' do
  title 'The IIS 10.0 website document directory must be in a separate partition from the IIS 10.0 websites system files.'
  desc 'The web document (home) directory is accessed by multiple anonymous users when the web server is in production. By locating the web document (home) directory on the same partition as the web server system file, the risk for unauthorized access to these protected files is increased. Additionally, having the web document (home) directory path on the same drive as the system folders also increases the potential for a drive space exhaustion attack.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name under review.

Click the "Advanced Settings" from the "Actions" pane.

Review the Physical Path.

If the Path is on the same partition as the OS, this is a finding.

Note: If this IIS 10.0 installation is supporting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name under review.

Click the "Advanced Settings" from the "Actions" pane.

Change the Physical Path to the new partition and directory location.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20225r311154_chk'
  tag severity: 'medium'
  tag gid: 'V-218752'
  tag rid: 'SV-218752r879643_rule'
  tag stig_id: 'IIST-SI-000224'
  tag gtitle: 'SRG-APP-000233-WSR-000146'
  tag fix_id: 'F-20223r311155_fix'
  tag 'documentable'
  tag legacy: ['SV-109329', 'V-100225']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
