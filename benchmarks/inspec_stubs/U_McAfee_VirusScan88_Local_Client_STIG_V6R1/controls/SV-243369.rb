control 'SV-243369' do
  title 'McAfee VirusScan On Delivery Email Scanner Properties must be configured to decode MIME encoded files.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and not clicking on hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to an email-borne virus but is self-contained rather than infecting an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Scan Items tab, locate the "Compressed files:" label. Ensure the "Decode MIME encoded files" option is selected.

Criteria:  If the "Decode MIME encoded files" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\DetectionOptions

Criteria:  If the value ScanMime is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Scan Items tab, locate the "Compressed files:" label. Select the "Decode MIME encoded files" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46644r722444_chk'
  tag severity: 'medium'
  tag gid: 'V-243369'
  tag rid: 'SV-243369r722446_rule'
  tag stig_id: 'DTAM027'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-46601r722445_fix'
  tag 'documentable'
  tag legacy: ['V-6599', 'SV-56396']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
