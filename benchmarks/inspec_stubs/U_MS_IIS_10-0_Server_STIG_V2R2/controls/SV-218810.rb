control 'SV-218810' do
  title 'Warning and error messages displayed to clients must be modified to minimize the identity of the IIS 10.0 web server, patches, loaded modules, and directory paths.'
  desc 'HTTP error pages contain information that could enable an attacker to gain access to an information system. Failure to prevent the sending of HTTP error pages with full information to remote requesters exposes internal configuration information to potential attackers.'
  desc 'check', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Error Pages" icon.

Click any error message, and then click "Edit Feature Setting" from the "Actions" Pane. This will apply to all error messages.

If the feature setting is not set to “Detailed errors for local requests and custom error pages for remote requests”, this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Error Pages" icon.

Click any error message, and then click "Edit Feature Setting" from the "Actions" Pane. This will apply to all error messages.

Set Feature Setting to “Detailed errors for local requests and custom error pages for remote requests”.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20282r310905_chk'
  tag severity: 'medium'
  tag gid: 'V-218810'
  tag rid: 'SV-218810r561041_rule'
  tag stig_id: 'IIST-SV-000140'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-20280r310906_fix'
  tag 'documentable'
  tag legacy: ['SV-109259', 'V-100155']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
