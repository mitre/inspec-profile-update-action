control 'SV-216967' do
  title 'McAfee VirusScan On-Delivery Email Scan Policies must be configured to send a notification email to the IAO, IAM, and/or ePO administrator when a threatened email message is detected.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments, and not clicking on hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses, but are self-contained, rather than infecting an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On Delivery Email Scan Policies. Under the Alerts tab, locate the "Email alert for user:" label. Ensure that "Send alert to mail user:" is selected. Verify that the email recipient information is complete for a notification email to be sent to the IAO/IAM and/or ePO administrator.

Criteria:  If the option "Send alert to mail user:" is selected and the email recipient information is complete for a notification email to be sent to the IAO, IAM, ePO administrator or System Administrator, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\AlertOptions

Criteria:  If the value bSendMailToUser is 0, this is a finding.
If the value for szSendTo is configured to any recipient other than the IAO, IAM, ePO Administrator, or System Administrator, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On Delivery Email Scan Policies. Under the Alerts tab, locate the "Email alert for user:" label. Select the "Send alert to mail user:" option. Enter the email recipient information for the notification email to be sent to the IAO/IAM and/or ePO administrator. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18197r309630_chk'
  tag severity: 'medium'
  tag gid: 'V-216967'
  tag rid: 'SV-216967r397873_rule'
  tag stig_id: 'DTAM158'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-18195r309631_fix'
  tag 'documentable'
  tag legacy: ['SV-55265', 'V-42537']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
