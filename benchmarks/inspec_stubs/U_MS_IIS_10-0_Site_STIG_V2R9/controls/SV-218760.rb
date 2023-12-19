control 'SV-218760' do
  title 'Warning and error messages displayed to clients must be modified to minimize the identity of the IIS 10.0 website, patches, loaded modules, and directory paths.'
  desc 'HTTP error pages contain information that could enable an attacker to gain access to an information system. Failure to prevent the sending of HTTP error pages with full information to remote requesters exposes internal configuration information to potential attackers.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name under review.

Double-click the "Error Pages" icon.

Click each error message and click "Edit Feature" setting from the "Actions" pane.

If any error message is not set to "Detailed errors for local requests and custom error pages for remote requests" or "Custom error pages", this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name under review.

Double-click the "Error Pages" icon.

Click each error message and click "Edit Feature" Setting from the "Actions" pane; set each error message to "Detailed errors for local requests and custom error pages for remote requests" or "Custom error pages".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20233r865208_chk'
  tag severity: 'medium'
  tag gid: 'V-218760'
  tag rid: 'SV-218760r879655_rule'
  tag stig_id: 'IIST-SI-000233'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-20231r865209_fix'
  tag 'documentable'
  tag legacy: ['SV-109345', 'V-100241']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
