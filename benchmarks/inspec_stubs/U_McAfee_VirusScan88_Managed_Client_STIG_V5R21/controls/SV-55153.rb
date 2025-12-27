control 'SV-55153' do
  title 'McAfee VirusScan On-Delivery Email Scan Policies must be configured to enable on-delivery email scanning.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments, and not clicking on hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses, but are self-contained, rather than infecting an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Delivery Email Scan Policies. Under the Scan Items tab, locate the "Scanning of email:" label. Ensure the "Enable on-delivery email scanning" option is selected. 

Criteria:  If the "Enable on-delivery email scanning" is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\GeneralOptions

Criteria:  If the value bEnabled is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On Delivery Email Scan Policies. Under the Scan Items tab, locate the "Scanning of email:" label. Select the "Enable on-delivery email scanning" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48782r4_chk'
  tag severity: 'medium'
  tag gid: 'V-6586'
  tag rid: 'SV-55153r2_rule'
  tag stig_id: 'DTAM021'
  tag gtitle: 'DTAM021-McAfee VirusScan Exchange scanner'
  tag fix_id: 'F-48011r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
