control 'SV-55189' do
  title 'McAfee VirusScan On Delivery Email Scan Policies must be configured to clean attachments as the first action for when an unwanted program is found.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments, and not clicking on hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses, but are self-contained, rather than infecting an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Delivery Email Scan Policies. Under the Actions tab, locate the "When an unwanted program is found:" label. Ensure that from the "Perform this action first:" pull down menu, "Clean attachments" is selected. 

Criteria:  If "Clean attachments" is selected for "Perform this action first", this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\ActionOptions

Criteria:  If the value for uAction_Program is not 5, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Delivery Email Scan Policies. Under the Actions tab, locate the "When an unwanted program is found:" label. From the "Perform this action first:" pull down menu, select "Clean attachments". Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48792r4_chk'
  tag severity: 'medium'
  tag gid: 'V-14652'
  tag rid: 'SV-55189r2_rule'
  tag stig_id: 'DTAM039'
  tag gtitle: 'DTAM039-McAfee VirusScan unwanted programs action'
  tag fix_id: 'F-48043r3_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
