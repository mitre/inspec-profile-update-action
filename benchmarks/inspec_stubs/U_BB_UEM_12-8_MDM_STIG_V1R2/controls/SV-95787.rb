control 'SV-95787' do
  title 'The BlackBerry UEM 12.8 Agent and Server must provide an alert via the trusted channel to the MDM server for the following event: required app is not installed on managed mobile device.'
  desc 'Audit logs and alerts enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify when the security posture of the device is not as expected, including when critical or security-relevant applications have not fully installed on mobile devices under management of the MDM platform. This enables the MDM administrator to take an appropriate remedial action.

SFR ID: FAU_ALT_EXT.2.1'
  desc 'check', 'This requirement is not applicable if the AO has not designated any required applications be installed on site managed mobile devices.

Verify a compliance email alert has been set up on the UEM server to alert if required apps are not installed on managed mobile devices.

- Have the UEM administrator determine the polling interval set up on the console (how often UEM checks compliance for managed mobile devices). (Note: For this review, have the administrator temporarily change the polling interval to 30 minutes or less.)
- Have the site UEM administrator identify one app required on site managed mobile devices. 
- Using a site managed mobile device, remove the required app from the mobile device.
- After the polling interval time has occurred, review the BlackBerry UEM server configuration to determine whether an alert was generated for non-compliance of the test mobile device.
***On the UEM console, click on the Managed Devices tab
***Verify a warning message and link is displayed
***Clink on the link and verify the test managed device and removed app are listed as out of compliance

If a compliance email alert has not been set up on the UEM server to alert if required apps are not installed on managed mobile devices, this is a finding.'
  desc 'fix', %q(This requirement is not applicable if the AO has not designated any required applications be installed on site managed mobile devices.

On the UEM console, do the following:
- Create a compliance email alert to alert if required apps are not installed on managed mobile devices.
- Set up an event/email notification.
- Set of a list of apps required to be installed on managed mobile devices.
- Create an event notification template.

Procedure details:
- For UEM Hosted Apps we deliver configuration to the device regarding the required applications.
- The device calls back to UEM to get the application (APP_SEND security audit).
- The device acknowledges getting the application either successfully or not (APP_DELIVERED security audit).

**Procedure for "Create a compliance email alert to alert if required apps are not installed on managed mobile devices"

The Administrator can create a compliance profile to Alert the user. Additionally, this compliance profile is monitored and an email is sent to the administrator if the device becomes non-compliant. 

1. The administrator accesses UEM >> menu bar, click Policies and Profiles >> Compliance >> Compliance.
2. Click the "Add" icon and type a name and description for the compliance profile.
(You can at this stage send a notification message to users when their devices become non-compliant if required.)
3. In the Email sent when violation is detected drop-down list, select an email template. To see the default compliance email, click Settings >> General settings >> Email templates.
4. In the Enforcement interval drop-down list, select how often BlackBerry UEM checks for compliance.
5. Expand Device notification sent out when violation is detected. Edit the message if necessary.
Note: If you want to use variables (supports default and custom variables) to populate notifications with user, device, and compliance information, you can also define and use your own custom variables using the management console. 
6. Click the tab for each device type in your organization and configure the appropriate values for each profile setting. 
7. Click "Add".

**Procedure for "Set up an event/email notification" 

1. Log in to UEM >> menu bar >> Settings >> General settings >> Event notifications.
2. On "Event notifications" tab, click "Add" icon.
3. Select event type, click "Next".
4. Date/time to send email notification drop-down list, select option > Always after an event: Email notifications are when the event occurs > click "Save". 
5. In Recipients field, select "Add new distribution list", click "Save".
6. In the Email template drop-down list, select the email template for event notification.
7. In the Status drop-down list, select "On" to enable event notification.
8. Click "Preview email", check the email address, and click "Save".

**Procedure for "Set of a list of apps required to be installed on managed mobile devices"

Note: If you are defining rules to restrict or allow specific apps, add those apps to the restricted apps list. 
1. On the menu bar, click "Apps".
2. Click "Restricted apps".
3. Click the "Add" icon and perform the task associated to IOS, Android, and Windows app restricted lists. 

**Procedure for "Create an event notification template"

To restrict built-in apps you must create a compliance profile and add the apps to the restricted app list in the profile.

On the menu bar, click Settings >> General settings.
1. Click "Email templates".
2. Click the "Add" icon and select "Event notification".
3. In the "Name" field, type a name to identify this template.
4. In the "Subject" field, complete one of the following tasks:
5. Clear the "Append event type to the email subject" check box and type a subject.
6. Leave the "Append event type to the email subject" check box selected, and type additional text in the subject field.
7. Leave the "Append event type to the email subject" check box selected.
8. In the Message field, type the body text of the event notification email.
9. Use the HTML editor to select the font format and to insert images (for example, your organization's logo).
10. To see sample text, click "Suggested text".
11. Click "Save".)
  impact 0.3
  ref 'DPMS Target Unified Endpoint Manager (UEM) 12.8'
  tag check_id: 'C-80757r1_chk'
  tag severity: 'low'
  tag gid: 'V-81075'
  tag rid: 'SV-95787r1_rule'
  tag stig_id: 'BUEM-12-812150'
  tag gtitle: 'PP-MDM-302002'
  tag fix_id: 'F-87875r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
