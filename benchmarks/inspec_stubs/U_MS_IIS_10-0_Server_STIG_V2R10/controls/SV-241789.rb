control 'SV-241789' do
  title 'ASP.NET version must be removed from the HTTP Response Header information.'
  desc 'HTTP Response Headers contain information that could enable an attacker to gain access to an information system. Failure to prevent the sending of certain HTTP Response Header information to remote requesters exposes internal configuration information to potential attackers.'
  desc 'check', 'Open the IIS 10.0 Manager.

Under the "Connections" pane on the left side of the management console, select the IIS 10.0 web server.

Click the HTTP Response Headers button.

Click to select the “X-Powered-By” HTTP Header.

If “X-Powered-By” has not been removed, this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.
Under the "Connections" pane on the left side of the management console, select the IIS 10.0 web server.
Click the HTTP Response Headers button.
Click to select the “X-Powered-By” HTTP Header.
Click “Remove” in the Actions Panel.
Note: This can be performed multiple ways, this is an example.'
  impact 0.3
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-45065r695282_chk'
  tag severity: 'low'
  tag gid: 'V-241789'
  tag rid: 'SV-241789r879655_rule'
  tag stig_id: 'IIST-SV-000215'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-45024r695283_fix'
  tag 'documentable'
  tag legacy: ['SV-54431', 'V-41854']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
