control 'SV-55540' do
  title 'The Symantec Endpoint Protection client Outlook Auto-Protect actions for when malware has been detected must be configured to Delete Risk if first action fails.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and to not click hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses but are self-contained rather than being designed to infect an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Outlook Auto-Protect tab -> Select the Actions tab -> Select Malware -> Ensure If first action fails is set to "Delete Risk". 

Criteria:  If first action fails is not set to "Delete Risk", this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key:
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan\\Malware
64 bit: 
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan\\Malware

Criteria:  If the value of "SecondAction" is 3, this is not a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Outlook Auto-Protect tab -> Select the Actions tab -> Select Malware -> Set if first action fails to "Delete Risk".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49084r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42812'
  tag rid: 'SV-55540r1_rule'
  tag stig_id: 'DTASEP079'
  tag gtitle: 'DTASEP079'
  tag fix_id: 'F-48398r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
