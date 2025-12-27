control 'SV-91135' do
  title 'Kona Site Defender providing content filtering must send an immediate (within seconds) alert to the system administrator, at a minimum, in response to malicious code detection.'
  desc 'Without an alert, security personnel may be unaware of an impending failure of the audit capability. This will impede the ability to perform forensic analysis and detect rate-based and other anomalies.

The ALG generates an immediate (within seconds) alert that notifies designated personnel of the incident. Sending a message to an unattended log or console does not meet this requirement since that will not be seen immediately. These messages should include a severity level indicator or code as an indicator of the criticality of the incident.'
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
  tag check_id: 'C-76099r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76439'
  tag rid: 'SV-91135r1_rule'
  tag stig_id: 'AKSD-WF-000030'
  tag gtitle: 'SRG-NET-000249-ALG-000146'
  tag fix_id: 'F-83117r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
