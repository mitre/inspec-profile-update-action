control 'SV-223238' do
  title 'SharePoint must support the requirement to initiate a session lock after 15 minutes of system or application inactivity has transpired.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system level and results in a system lock, but it may be at the application level, where the application interface window is secured instead. The organization defines the period of inactivity that shall pass before a session lock is initiated, so this must be configurable."
  desc 'check', 'Review the SharePoint server configuration to ensure a session lock occurs after 15 minutes of inactivity.

In SharePoint Central Administration, click Application Management. 

On the Application Management page, in the Web Applications section, click Manage web applications. 

Verify that each web application meets this requirement.
- Select the web application.
- Select General Settings >> General Settings.
- Navigate to the Web Page Security Validation section.
- Verify that the Security Validation is "On" and set to expire after 15 minutes or less. 

If Security Validation is "Off" or if the default time-out period is not set to 15 minutes or less for any of the web applications, this is a finding.'
  desc 'fix', 'Configure the SharePoint server to lock the session lock after 15 minutes of inactivity.

In SharePoint Central Administration, click Application Management. 

On the Application Management page, in the Web Applications section, click Manage web applications. 

Perform the following steps for each web application.
- Select web application.
- Select General Settings >> General Settings.
- Navigate to Web Page Security Validation.
- Set the "Security validation is:" property to On.
- Set the "Security validation expires:" property to After.
- Set the default time-out period to 15 minutes or less.
- Select OK to save settings.'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24911r430774_chk'
  tag severity: 'medium'
  tag gid: 'V-223238'
  tag rid: 'SV-223238r612235_rule'
  tag stig_id: 'SP13-00-000005'
  tag gtitle: 'SRG-APP-000003'
  tag fix_id: 'F-24899r430775_fix'
  tag 'documentable'
  tag legacy: ['SV-74349', 'V-59919']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
