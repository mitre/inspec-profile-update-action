control 'SV-243436' do
  title 'McAfee VirusScan On Delivery Email Scanner Properties must be configured to delete attachments if the first action fails for when an unwanted attachment is found.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and not clicking on hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to an email-borne virus but is self-contained rather than infecting an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Actions tab, locate the "When an unwanted attachment is found:" label. Ensure that from the "If the first action fails, then perform this action:" pull down menu, "Delete attachments" is selected. 

Criteria:  If "Delete attachments" is selected for "If the first action fails, then perform this action:", this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\ActionOptions

Criteria:  If the value for uSecAction_Program is not 4, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Actions tab, locate the "When an unwanted attachment is found:" label. From the "If the first action fails, then perform this action:" pull down menu, select "Delete attachments".

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46711r722645_chk'
  tag severity: 'medium'
  tag gid: 'V-243436'
  tag rid: 'SV-243436r722647_rule'
  tag stig_id: 'DTAM163'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-46668r722646_fix'
  tag 'documentable'
  tag legacy: ['V-6469', 'SV-56369']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
