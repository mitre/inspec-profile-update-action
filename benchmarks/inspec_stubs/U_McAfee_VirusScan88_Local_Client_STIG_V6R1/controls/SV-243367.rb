control 'SV-243367' do
  title 'McAfee VirusScan On-Delivery Email Scanner must be configured to find unknown program threats and trojans.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and not clicking on hyperlinks, etc., from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to an email-borne virus but is self-contained rather than infecting an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Scan Items tab, locate the "Heuristics:" label. Ensure the "Find unknown program threats and trojans" option is selected.

Criteria:  If the "Find unknown program threats and trojans" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\DetectionOptions

Criteria:  If the value dwProgramHeuristicsLevel is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Scan Items tab, locate the "Heuristics:" label. Select the "Find unknown program threats and trojans" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46642r722438_chk'
  tag severity: 'medium'
  tag gid: 'V-243367'
  tag rid: 'SV-243367r722440_rule'
  tag stig_id: 'DTAM022'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-46599r722439_fix'
  tag 'documentable'
  tag legacy: ['V-42562', 'SV-55290']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
