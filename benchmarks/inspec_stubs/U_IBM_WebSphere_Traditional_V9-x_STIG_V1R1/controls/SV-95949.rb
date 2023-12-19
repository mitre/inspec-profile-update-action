control 'SV-95949' do
  title 'The WebSphere Application Server management interface must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'To establish acceptance of system usage policy, a click-through banner at the application server management interface logon is required. The banner shall prevent further activity on the application server unless and until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".'
  desc 'check', 'Point browser to the URL of the WebSphere administration console.

If the Standard Mandatory DoD Notice and Consent Banner is not retained until the user acknowledges the usage conditions, this is a finding.'
  desc 'fix', 'Open the file ${WAS_HOME}/properties/login.info.

Follow the instructions in the HTML comment section to create the pre-logon banner.

Enter the Standard DoD Mandatory Notice and Consent banner into the HTML section.

If logged on to the admin console, log out and log back on to validate the changes.

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80921r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81235'
  tag rid: 'SV-95949r1_rule'
  tag stig_id: 'WBSP-AS-000320'
  tag gtitle: 'SRG-APP-000069-AS-000036'
  tag fix_id: 'F-88015r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
