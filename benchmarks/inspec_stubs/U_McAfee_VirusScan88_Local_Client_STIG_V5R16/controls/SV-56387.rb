control 'SV-56387' do
  title 'McAfee VirusScan On Delivery Email Scanner Properties must be configured to find unknown macro threats.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and not clicking on hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to an email-borne virus but is self-contained rather than infecting an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Scan Items tab, locate the "Heuristics:" label. Ensure the "Find unknown macro threats" option is selected.

Criteria:  If the "Find unknown macro threats" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email scanner\\Outlook\\OnDelivery\\DetectionOptions

Criteria:  If the value dwMacroHeuristicsLevel is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Scan Items tab, locate the "Heuristics:" label. Select the "Find unknown macro threats" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49304r3_chk'
  tag severity: 'medium'
  tag gid: 'V-6588'
  tag rid: 'SV-56387r2_rule'
  tag stig_id: 'DTAM023'
  tag gtitle: 'DTAM023- McAfee VirusScan find unknown macro virus'
  tag fix_id: 'F-49074r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
