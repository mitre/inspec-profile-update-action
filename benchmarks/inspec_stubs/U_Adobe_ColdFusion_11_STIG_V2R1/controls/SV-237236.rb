control 'SV-237236' do
  title 'ColdFusion must have notifications enabled when a server update is available.'
  desc 'Security flaws with software applications are discovered daily.  Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities.  To configure the software to discover that a new patch is available is important since administrators may be responsible for multiple servers running different applications and services, making it difficult for the administrator to constantly check for updates.  Enabling the automatic check informs the administrator, allows him to investigate the patch and what is needed to apply the patch and schedule any outages that might be needed, thereby permitting the patch to be installed quickly and efficiently.

Having "Check for updates every" checked causes ColdFusion to look for updates every set number of days.  Entering a list of email addresses to notify guarantees a notification is sent to the administrator.'
  desc 'check', %q(Determine if the ColdFusion server has access to either the Adobe patch repository or an internally maintained patch repository.  This may be determined by interviewing the administrator or by reviewing ColdFusion baseline documentation.

If the ColdFusion server has access to a patch repository, the server must notify administrators when updates are available.  To verify that the server is notifying administrators, within the Administrator Console, navigate to the "Updates" page under the "Server Updates" menu.  Select the "Settings" tab and verify that the "Check for updates every" is checked, that a positive value is entered for the "days" value and that at least one email address is entered for notification.

If "Check for updates every" is not checked, the "days" value is empty or less than 1, or the "If updates are available, send email notification to" parameter is empty, this is a finding.

If the ColdFusion server does not have access to a patch repository, then a documented notification process must be in place along with the administrator's enrollment in the Adobe automated patch notification service.  To validate enrollment, a verification email or patch notification email can be used.

If the administrators are not enrolled in the Adobe patch notification service or the process is not documented, this is a finding.)
  desc 'fix', 'If the ColdFusion server has access to a patch repository, navigate to the "Updates" page under the "Server Updates" menu.  Select the "Settings" tab and check the "Check for updates every" setting, enter a value greater than 0 for the "days" setting, and enter email addresses for notification.  Select the "Submit Changes" button to save the new settings.

If the ColdFusion server does not have access to a patch repository, document the process to enroll into the Adobe patch notification service and enroll all administrators in the notification service.'
  impact 0.3
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40455r641801_chk'
  tag severity: 'low'
  tag gid: 'V-237236'
  tag rid: 'SV-237236r641803_rule'
  tag stig_id: 'CF11-06-000227'
  tag gtitle: 'SRG-APP-000456-AS-000266'
  tag fix_id: 'F-40418r641802_fix'
  tag 'documentable'
  tag legacy: ['SV-77035', 'V-62545']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
