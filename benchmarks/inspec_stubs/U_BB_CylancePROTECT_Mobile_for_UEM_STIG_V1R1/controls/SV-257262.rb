control 'SV-257262' do
  title 'CylancePROTECT Mobile must be configured with the following compliance action when a compliance event occurs:
-Notify Administrator (send event notification).'
  desc 'When a compliance failure is detected, compliance actions must be implemented immediately to limit exposure of sensitive data and unauthorized access to the mobile device.'
  desc 'check', 'Verify the following compliance action for CylancePROTECT Mobile has been enabled:
-Notify Administrator (send event notification).

1. Log on to the BlackBerry UEM console.
2. On the menu bar, click Settings >> General settings.
3. Click "Event notifications".
4. Verify each of the following BlackBerry Protect notifications are listed: "Safe Browsing", "Malicious app removed from UEM", "Malicious app detected on device", and "Sideloaded app detected on app".

If all four of the BlackBerry Protect notifications listed above are not enabled, this is a finding.'
  desc 'fix', 'Enable the following compliance action for CylancePROTECT Mobile:
-Notify Administrator (send event notification).

1. Log on to the BlackBerry UEM console.
2. On the menu bar, click Settings >> General settings.
3. Click "Event notifications".
a. On the "Event notifications" tab, click "Add".
b. Select event type "BlackBerry Protect".
c. Click one of the following selections: "Safe Browsing", "Malicious app removed from UEM", "Malicious app detected on device", or "Sideloaded app detected on app".
d. Click "Next".
4. In the Date/time to send email notification drop-down list, select one of the following options:
a. Always after an event: Email notifications are sent whenever the event occurs.
b. Any preconfigured schedule in the list.
c. Add new scheduler: Create a schedule and click "Save".
5. In the Recipients field, select one of the following options:
a. Add new distribution list: Create a distribution list and click "Save".
b. Any preconfigured distribution list.
6. In the email template drop-down list, select the email template to use for the event notification.
7. In the Status drop-down list, select "On" to enable the event notification.
8. Click "Preview email" to see the event notification email and the list of email addresses for the recipients.
9. Click "Save".
10. Repeat steps 3–9 for each of the possible BlackBerry Protect event notifications ("Safe Browsing", "Malicious app removed from UEM", "Malicious app detected on device", "Sideloaded app detected on app").'
  impact 0.5
  ref 'DPMS Target BlackBerry CylancePROTECT Mobile for UEM'
  tag check_id: 'C-60946r918368_chk'
  tag severity: 'medium'
  tag gid: 'V-257262'
  tag rid: 'SV-257262r918370_rule'
  tag stig_id: 'BBCP-00-012800'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-60888r918369_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
