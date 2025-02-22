control 'SV-56391' do
  title 'McAfee VirusScan On Delivery Email Scanner Properties, When a threat is found, must be configured to clean attachments as the first action.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and not clicking on hyperlinks, etc., from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to an email-borne virus but is self-contained rather than infecting an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Actions tab, locate the "When a threat is found:" label. Ensure the "Perform this action first:" pull down menu has "Clean attachments" selected. 

Criteria:  If "Clean attachments" is selected for "Perform this action first", this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\ActionOptions

Criteria:  If the value for uAction is not 5, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Actions tab, locate the "When a threat is found:" label. From the "Perform this action first:" pull down menu, select "Clean attachments". 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49308r3_chk'
  tag severity: 'medium'
  tag gid: 'V-6592'
  tag rid: 'SV-56391r2_rule'
  tag stig_id: 'DTAM029'
  tag gtitle: 'DTAM029-McAfee VirusScan allowed actions email'
  tag fix_id: 'F-49113r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
