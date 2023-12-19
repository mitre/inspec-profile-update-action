control 'SV-93365' do
  title 'The Tanium Server console must be configured to initiate a session lock after a 15-minute period of inactivity.'
  desc 'The Tanium Console, when CAC is enabled, will initiate a session lock based upon the ActivClient or other Smart Card software.

By initiating the session lock, the console will be locked and not allow unauthorized access by anyone other than the original user.

Although this setting does not apply when CAC is enabled, it should be explicitly disabled in the event CAC authentication is ever broken or removed.'
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

After logging on, in the top right corner of the UI select the drop-down arrow and click on "Preferences".

Verify the "Suspend console automatically if no activity detected for:" is configured to a value of "15" minutes or less.

If the "Suspend console automatically if no activity detected for:" is not configured to a value of "15" minutes or less, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

After logging on, in the top right corner of the UI select the drop-down arrow and click on "Preferences".

For "Suspend console automatically if no activity detected for:", select a value of "15" minutes or less.

Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78229r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78659'
  tag rid: 'SV-93365r1_rule'
  tag stig_id: 'TANS-SV-000002'
  tag gtitle: 'SRG-APP-000003'
  tag fix_id: 'F-85395r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
