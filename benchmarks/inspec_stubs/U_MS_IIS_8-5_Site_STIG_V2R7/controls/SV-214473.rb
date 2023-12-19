control 'SV-214473' do
  title 'Debugging and trace information used to diagnose the IIS 8.5 website must be disabled.'
  desc 'Setting compilation debug to false ensures detailed error information does not inadvertently display during live application usage, mitigating the risk of application information being displayed to users.'
  desc 'check', 'Note: If the ".NET feature" is not installed, this check is Not Applicable.

Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click the site name under review.

Double-click ".NET Compilation".

Scroll down to the "Behavior" section and verify the value for "Debug" is set to "False".

If the "Debug" value is not set to "False", this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click the site name under review.

Double-click ".NET Compilation".

Scroll down to the "Behavior" section and set the value for "Debug" to "False".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15682r310623_chk'
  tag severity: 'medium'
  tag gid: 'V-214473'
  tag rid: 'SV-214473r879655_rule'
  tag stig_id: 'IISW-SI-000234'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-15680r310624_fix'
  tag 'documentable'
  tag legacy: ['SV-91533', 'V-76837']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
