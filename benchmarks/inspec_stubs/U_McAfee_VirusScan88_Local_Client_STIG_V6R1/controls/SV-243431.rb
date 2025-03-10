control 'SV-243431' do
  title 'McAfee VirusScan On-Delivery Email Scanner must be configured to send a notification email to the IAO, IAM and/or ePO administrator when a threatening email message is detected.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and not clicking on hyperlinks, etc., from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to an email-borne virus but is self-contained rather than infecting an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Alerts tab, locate the "Email alert:" label. Ensure "Send alert to mail user:" is selected. 
Click on Configure. Verify the email recipient information is configured for a notification email to be sent to the ISSO, ISSM, ePO administrator, or System Administrator.

Criteria:  If the option "Email alert:" is selected and the email recipient information is configured for a notification email to be sent to ISSO, ISSM,ePO administrator, or System Administrator, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\AlertOptions

Criteria:  If the value bSendMailToUser is 0, this is a finding.
If the value for szSendTo is configured to any recipient other than the ISSO, ISSM,ePO Administrator, or System Administrator, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Alerts tab, locate the "Email alert:" label. 
Click on Configure. Select the "Send alert to mail user:" option. Enter the email recipient information for the notification email to be sent to the ISSO, ISSM,ePO administrator, or System Administrator. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46706r722630_chk'
  tag severity: 'medium'
  tag gid: 'V-243431'
  tag rid: 'SV-243431r722632_rule'
  tag stig_id: 'DTAM158'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-46663r722631_fix'
  tag 'documentable'
  tag legacy: ['V-42567', 'SV-55295']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
