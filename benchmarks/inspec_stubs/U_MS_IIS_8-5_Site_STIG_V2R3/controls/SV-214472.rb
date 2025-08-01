control 'SV-214472' do
  title 'Warning and error messages displayed to clients must be modified to minimize the identity of the IIS 8.5 website, patches, loaded modules, and directory paths.'
  desc 'HTTP error pages contain information that could enable an attacker to gain access to an information system. Failure to prevent the sending of HTTP error pages with full information to remote requesters exposes internal configuration information to potential attackers.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click the site name under review.

Double-click the "Error Pages" icon.

Click each error message and click "Edit Feature" setting from the "Actions" pane.

If any error message is not set to “Detailed errors for local requests and custom error pages for remote requests”, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click the site name under review.

Double-click the "Error Pages" icon.

Click each error message and click "Edit Feature" Setting from the "Actions" pane; set each error message to “Detailed errors for local requests and custom error pages for remote requests”.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15681r310620_chk'
  tag severity: 'medium'
  tag gid: 'V-214472'
  tag rid: 'SV-214472r508659_rule'
  tag stig_id: 'IISW-SI-000233'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-15679r310621_fix'
  tag 'documentable'
  tag legacy: ['SV-91531', 'V-76835']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
