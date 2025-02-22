control 'SV-32662' do
  title 'Debug must be turned off on a production website.'
  desc 'Setting compilation debug to false ensures detailed error information does not inadvertently display during live application usage, mitigating the risk of application information being display to users.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click .NET Compilation.
4. Scroll down to the Behavior section and ensure the value for Debug is set to False. If not, this is a finding.

NOTE: If the .NET feature is not installed, this check is not applicable.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click .NET Compilation
4. Scroll down to the Behavior section and set the value for Debug to False.'
  impact 0.3
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32876r1_chk'
  tag severity: 'low'
  tag gid: 'V-26011'
  tag rid: 'SV-32662r2_rule'
  tag stig_id: 'WA000-WI6140 IIS7'
  tag gtitle: 'WA000-WI6140'
  tag fix_id: 'F-29027r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
