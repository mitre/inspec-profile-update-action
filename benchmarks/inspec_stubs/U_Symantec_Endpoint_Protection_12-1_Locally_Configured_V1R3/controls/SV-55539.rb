control 'SV-55539' do
  title 'The Symantec Endpoint Protection client Outlook Auto-Protect actions for when malware has been detected must be configured to Clean Risk as first action.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and to not click hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses but are self-contained rather than being designed to infect an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Outlook Auto-Protect tab -> Select the Actions tab -> Select Malware -> Ensure first action is set to "Clean Risk".

Criteria:  If first action is not set to "Clean Risk", this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key:
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan\\Malware
64 bit: 
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan\\Malware

Criteria:  If the value of "FirstAction" is 5, this is not a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Outlook Auto-Protect tab -> Select the Actions tab -> Select Malware -> Set first action to "Clean Risk".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49083r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42811'
  tag rid: 'SV-55539r1_rule'
  tag stig_id: 'DTASEP078'
  tag gtitle: 'DTASEP078'
  tag fix_id: 'F-48397r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
