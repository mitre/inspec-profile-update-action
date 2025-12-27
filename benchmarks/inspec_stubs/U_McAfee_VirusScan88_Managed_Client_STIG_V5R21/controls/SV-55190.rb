control 'SV-55190' do
  title 'McAfee VirusScan On Delivery Email Scan Policies must be configured to delete attachments if the first action fails for when an unwanted program is found.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments, and not clicking on hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses, but are self-contained, rather than infecting an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On Delivery Email Scan Policies. Under the Actions tab, locate the "When an unwanted program is found:" label. Ensure that from the "If the first action fails, then perform this action:" pull down menu, "Delete attachments" is selected. 

Criteria:  If "Delete attachments" is selected for "If the first action fails, then perform this action:", this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\ActionOptions

Criteria: If the value for uSecAction_Program is not 4, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On Delivery Email Scan Policies. Under the Actions tab, locate the "When an unwanted program is found:" label. From the "If the first action fails, then perform this action:" pull down menu, select "Delete attachments". Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48793r5_chk'
  tag severity: 'medium'
  tag gid: 'V-42500'
  tag rid: 'SV-55190r2_rule'
  tag stig_id: 'DTAM163'
  tag gtitle: 'DTAM163-McAfee VirusScan Email on-delivery unwanted program second action'
  tag fix_id: 'F-48044r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
