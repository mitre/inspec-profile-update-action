control 'SV-108145' do
  title 'The UEM Agent must provide an alert via the trusted channel to the BlackBerry UEM 12.11 server for the following event: change in enrollment state.'
  desc 'Alerts providing notification of a change in enrollment state facilitate verification of the correct operation of security functions. When a BlackBerry UEM 12.11 server receives such an alert from a UEM Agent, it indicates that the security policy may no longer be enforced on the mobile device. This enables the UEM administrator to take an appropriate remedial action.

SFR ID: FAU_ALT_EXT.2.1'
  desc 'check', 'Review the BlackBerry UEM server configuration to determine whether the UEM alerts when required applications are not installed or app updates are not installed. 

Remove a required application from the device.

Verify an email notification has been sent to the administrator. 

Note: UEM will automatically alert if an app is not updated if the alert for a required app is correctly configured. A required app "update" is considered the same thing as a "required" app.

If an email notification is not sent to the administrator when a required application is removed from the mobile device, this is a finding.'
  desc 'fix', 'From the server perspective:
- For UEM Hosted Apps, deliver the configuration to the device regarding the required applications.
- The device calls back to UEM to get the application (APP_SEND security audit).
- The device acknowledges getting the application either successfully or not (APP_DELIVERED security audit).

The Administrator can create a compliance profile to alert the user. This compliance profile is monitored and an email is sent to the administrator if the device becomes non-compliant. 

1. The administrator accesses the "UEM" menu bar.
2. Select >> Policies and Profiles >> Compliance >> Compliance.
3. Click the "Add" icon.
4. Type a name and description for the compliance profile.
(At this stage, a notification message can be sent to users when their devices become noncompliant, if required.)
5. In the email sent when a violation is detected, select an email template. To see the default compliance email, click Settings >> General settings >> Email templates.
6. In the "Enforcement interval" drop-down list, select how often BlackBerry UEM checks for compliance.
7. Expand Device notification sent out when violation is detected and edit the message, if necessary.
Note: If using variables (supports default and custom variables) to populate notifications with user, device, and compliance information, custom variables can also be defined using the management console. 
8. Click the tab for each device type in the organization.
9. Select the "Required app is not installed" checkbox for each profile setting. 
10. Click "Add".

Set up event notifications to alert administrators by email about a device that becomes noncompliant. 

1. Log in to UEM >> menu bar >> Settings >> General settings >> Event notifications.
2. On "Event notifications" tab, click "Add" icon.
3. Select event type (Compliance breached).
4. Click "Next".
5. From Date/time to send email notification drop-down list, select option "Always after an event: Email notifications are when the event occurs" and click "Save". 
6. In "Recipients" field, select "Add new distribution list".
7. Click "Save".
8. In the "email template" drop-down list, select the "email template for event notification".
9. In the "Status" drop-down list, select "On" to enable event notification.
10. Click "Preview email".
11. Check the email text to make sure it is correct.
12. Click "Save".'
  impact 0.5
  ref 'DPMS Target BlackBerry Unified Endpoint Manager (UEM) 12.11'
  tag check_id: 'C-97881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99041'
  tag rid: 'SV-108145r1_rule'
  tag stig_id: 'BUEM-12-113010'
  tag gtitle: 'PP-MDM-402001'
  tag fix_id: 'F-104717r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end
