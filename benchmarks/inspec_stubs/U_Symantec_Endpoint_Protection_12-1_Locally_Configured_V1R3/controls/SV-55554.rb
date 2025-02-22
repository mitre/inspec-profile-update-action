control 'SV-55554' do
  title 'The Symantec Endpoint Protection Internet Email Auto-Protect must be enabled.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and to not click hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses but are self-contained rather than being designed to infect an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Note: This check is Not Applicable to 64-bit system running SEP 12.

GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Internet Email Auto-Protect tab -> Ensure "Enable Internet Email Auto-Protect" is selected. 

 Criteria:  If "Enable Internet Email Auto-Protect" is not selected, this is a finding. 

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\InternetMail\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\InternetMail\\RealTimeScan

Criteria:  If the value of "OnOff" is not "1", this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Internet Email Auto-Protect tab -> Select "Enable Internet Email Auto-Protect".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49098r3_chk'
  tag severity: 'medium'
  tag gid: 'V-42826'
  tag rid: 'SV-55554r2_rule'
  tag stig_id: 'DTASEP093'
  tag gtitle: 'DTASEP093'
  tag fix_id: 'F-48412r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001668']
  tag nist: ['SI-3 a']
end
