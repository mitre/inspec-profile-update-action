control 'SV-55537' do
  title 'The Symantec Endpoint Protection client Outlook Auto-Protect must be configured to send a notification email to the IAO, IAM, and/or ePO administrator when a threatened email message is detected.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and to not click hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses but are self-contained rather than being designed to infect an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Outlook Auto-Protect tab, under Email Messages -> Ensure "Send email to others" is selected -> Select Others -> Ensure the IAO, IAM, and/or ePO administrator are listed.

Criteria:  If "Send email to others" is  not selected, this is a finding. 
If "Send email to others" is  selected and the IAO, IAM, and/ or the ePO administrator email addresses are not listed, this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan

Criteria:  If the value of NotifySelected is not 1, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Outlook Auto-Protect tab, under Email Messages -> Select "Send email to others" -> Select Others -> Add  the IAO, IAM, and/or ePO administrator email addresses.'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49081r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42809'
  tag rid: 'SV-55537r1_rule'
  tag stig_id: 'DTASEP076'
  tag gtitle: 'DTASEP076'
  tag fix_id: 'F-48395r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001668']
  tag nist: ['SI-3 a']
end
