control 'SV-32682' do
  title 'The production web-site must be configured to prevent detailed HTTP error pages from being sent to remote clients.'
  desc 'HTTP error pages contain information that could enable an attacker to gain access to an information system. Failure to prevent the sending of HTTP error pages with full information to remote requesters exposes internal configuration information to potential attackers.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click the Error Pages icon.
4. Click each error message and click Edit Feature Setting from the Actions Pane. If any error message is not set to “Detailed errors for local requests and custom error pages for remote requests”, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click the Error Pages icon.
4. Click each error message and click Edit Feature Setting from the Actions Pane; set each error message to “Detailed errors for local requests and custom error pages for remote requests”.'
  impact 0.3
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32885r1_chk'
  tag severity: 'low'
  tag gid: 'V-26031'
  tag rid: 'SV-32682r2_rule'
  tag stig_id: 'WA000-WI6165'
  tag gtitle: 'WA000-WI6165 IIS7'
  tag fix_id: 'F-29033r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
