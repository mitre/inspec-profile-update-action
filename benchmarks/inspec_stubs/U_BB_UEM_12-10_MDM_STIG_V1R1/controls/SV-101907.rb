control 'SV-101907' do
  title 'The Blackberry UEM Client Agent must be configured to provide an alert via the trusted channel to the Blackberry UEM 12.10 Server for the following events: - Failure to install an application from the Blackberry UEM 12.10 Server; - Failure to update an application from the Blackberry UEM 12.10 Server.'
  desc 'Audit logs and alerts enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify when the security posture of the device is not as expected, including when a critical or security-relevant application was not properly updated on mobile devices under management of the UEM platform. This enables the UEM administrator to take an appropriate remedial action.

SFR ID: FAU_ALT_EXT.2.1'
  desc 'check', 'Review the BlackBerry UEM server configuration to determine whether the UEM alerts, when required applications are not installed, or app updates are not installed. 

Remove a required application from the device.

Verify an email notification has been sent to the administrator. Note: UEM will automatically alert if an app is not updated if the alert for a required app is correctly configured. A required app "update" is considered the same thing as a "required" app.

If an email notification is not sent to the administrator when a required application is removed from the mobile device, this is a finding.'
  desc 'fix', 'From the server perspective we do the following:
- For UEM Hosted Apps we deliver configuration to the device regarding the required applications;
- The device calls back to UEM to get the application (APP_SEND security audit);
- The device acknowledges getting the application either successfully or not (APP_DELIVERED security audit).

The Administrator can create a compliance profile to Alert the user. Additionally, this compliance profile is monitored and an email is sent to the administrator if the device becomes non-compliant. 

1. The administrator accesses "UEM" menu bar.
2. Select >> Policies and Profiles >> Compliance >> Compliance.
3. Click the "Add" icon
4. Type a name and description for the compliance profile.
(You can at this stage send a notification message to users when their devices become non-compliant, if required)
5. In the email sent when a violation is detected, select an email template. To see the default compliance email, click Settings >> General settings >> Email templates.
6. In the "Enforcement interval" drop-down list, select how often BlackBerry UEM checks for compliance.
7. Expand Device notification sent out when violation is detected and edit the message, if necessary.
Note: If you want to use variables (supports default and custom variables) to populate notifications with user, device, and compliance information, you can also define and use your own custom variables using the management console. 
8. Click the tab for each device type in your organization.
9. Select the "Required app is not installed" checkbox for each profile setting. 
10. Click "Add".

You then set up event notifications to alert administrators by email about a device that becomes non-compliant. 

1. Log onto UEM >> menu bar >> Settings >> General settings >> Event notifications.
2. On "Event notifications" tab, click "Add" icon.
3. Select event type (Compliance breached).
4. Click "Next".
5. Date/time to send email notification drop-down list, select option >> Always after an event: Email notifications are when the event occurs >> click "Save". 
6. In "Recipients" field, select "Add new distribution list".
7. Click "Save".
8. In the "email template" drop-down list, select the "email template for event notification".
9. In the "Status" drop-down list, select "On" to enable event notification.
10. Click "Preview email".
11. Check the email text to make sure it is correct.
12. Click "Save".'
  impact 0.5
  ref 'DPMS Target BlackBerry Unified Endpoint Manager (UEM) 12.10'
  tag check_id: 'C-90963r1_chk'
  tag severity: 'medium'
  tag gid: 'V-91805'
  tag rid: 'SV-101907r1_rule'
  tag stig_id: 'BUEM-12-101220'
  tag gtitle: 'PP-MDM-302003'
  tag fix_id: 'F-98007r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
