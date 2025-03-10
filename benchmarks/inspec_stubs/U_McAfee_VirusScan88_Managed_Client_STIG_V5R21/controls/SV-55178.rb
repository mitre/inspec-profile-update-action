control 'SV-55178' do
  title 'McAfee VirusScan On Delivery Email Scan Policies, when a threat is found, must be configured to clean attachments as the first action.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments, and not clicking on hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses, but are self-contained, rather than infecting an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Delivery Email Scan Policies. Under the Actions tab, locate the "When a threat is found:" label. Ensure that for the "Perform this action first:" pull down menu, "Clean attachments" is selected. 

Criteria:  If "Clean attachments" is selected for "Perform this action first", this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\ActionOptions

Criteria:  If the value for uAction is not 5, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On Delivery Email Scan Policies. Under the Actions tab, locate the "When a threat is found:" label. For the "Perform this action first:" pull down menu, select "Clean attachments". Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48788r5_chk'
  tag severity: 'medium'
  tag gid: 'V-6592'
  tag rid: 'SV-55178r2_rule'
  tag stig_id: 'DTAM029'
  tag gtitle: 'DTAM029-McAfee VirusScan allowed actions email'
  tag fix_id: 'F-48032r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
