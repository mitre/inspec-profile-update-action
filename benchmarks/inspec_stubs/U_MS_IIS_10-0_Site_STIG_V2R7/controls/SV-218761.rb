control 'SV-218761' do
  title 'Debugging and trace information used to diagnose the IIS 10.0 website must be disabled.'
  desc 'Setting compilation debug to false ensures detailed error information does not inadvertently display during live application usage, mitigating the risk of application information being displayed to users.'
  desc 'check', 'Note: If the ".NET feature" is not installed, this check is Not Applicable.

Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name under review.

Double-click ".NET Compilation".

Scroll down to the "Behavior" section and verify the value for "Debug" is set to "False".

If the "Debug" value is not set to "False", this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name under review.

Double-click ".NET Compilation".

Scroll down to the "Behavior" section and set the value for "Debug" to "False".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20234r311181_chk'
  tag severity: 'medium'
  tag gid: 'V-218761'
  tag rid: 'SV-218761r558649_rule'
  tag stig_id: 'IIST-SI-000234'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-20232r311182_fix'
  tag 'documentable'
  tag legacy: ['SV-109347', 'V-100243']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
