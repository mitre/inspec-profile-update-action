control 'SV-91141' do
  title 'Kona Site Defender providing content filtering must send an alert to, at a minimum, the ISSO and ISSM when detection events occur.'
  desc "Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

Since these incidents require immediate action, these messages are assigned a critical or Level 1 priority/severity, depending on the system's priority schema.

In accordance with CCI-001242, the ALG that provides content inspection services is a real-time intrusion detection system. These systems must generate an alert when detection events from real-time monitoring occur. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel."
  desc 'check', 'Confirm Kona Site Defender is configured to alert the ISSO, ISSM, and SA when detection events occur:

1. Log in to the Akamai Luna Portal (Caution-https://control.akamai.com).
2. Click the "Monitor" tab.
3. Under the "Security" section select "Security Monitor".
4. Click the "Notification" button (an icon shaped like a triangle with an exclamation point on the inside)
5. Click the "Configure Notification" button shaped like a plus sign.
6. Confirm that notifications are being sent when "Mitigated" is greater than (>) "1".

If the alerts are not being sent, this is a finding.'
  desc 'fix', 'Configure Kona Site Defender to alert the ISSO, ISSM, and SA when detection events occur:

1. Log in to the Akamai Luna Portal (Caution-https://control.akamai.com).
2. Click the "Monitor" tab.
3. Under the "Security" section select "Security Monitor".
4. Click the "Notification" button (an icon shaped like a triangle with an exclamation point on the inside)
5. Click the "Configure Notification" button shaped like a plus sign.
6. Click the "Add Notification" button shaped like a plus sign.
7. Click the "Show Advanced View" link.
8. Set the "Notification Name" to "WAF Activity Mitigated"
9. Enter a more detailed description in the “Description” text box.
10. Set the priority to "high".
11. In the "Notify When:" section, set "Mitigated" to greater than (>) 1.
12. Set the “Apply Filter:” dropdowns to “Host Name” and “Contains”, and enter the applicable host name in the text box.
13. Set "During:" to "1 Minute".
14. Set "Notify After:" to "1" occurrences.
15. Select the "Host Name" check box in the "For:" area.
16. Add the ISSO and ISSM emails to the "Email to:" field.
17. Click the “Save” button.'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security ALG'
  tag check_id: 'C-76105r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76445'
  tag rid: 'SV-91141r1_rule'
  tag stig_id: 'AKSD-WF-000034'
  tag gtitle: 'SRG-NET-000392-ALG-000141'
  tag fix_id: 'F-83123r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
