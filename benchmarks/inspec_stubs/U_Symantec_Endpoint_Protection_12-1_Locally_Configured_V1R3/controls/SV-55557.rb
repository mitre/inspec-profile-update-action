control 'SV-55557' do
  title 'The Symantec Endpoint Protection client  Internet Email Auto-Protect  for notification must be configured to insert a warning into email messages when a message part has been deleted, cleaned, or quarantined.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and to not click hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses but are self-contained rather than being designed to infect an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Internet Email Auto-Protect tab, under Email Messages -> Ensure "Insert a warning into the email message" is selected. 

Criteria:  If "Insert a warning into the email message" is not selected, this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\InternetMail\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\InternetMail\\RealTimeScan

Criteria:  If the value of InsertWarning is not 1, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Internet Email Auto-Protect tab, under Email Messages -> Select "Insert a warning into the email message".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49101r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42829'
  tag rid: 'SV-55557r1_rule'
  tag stig_id: 'DTASEP096'
  tag gtitle: 'DTASEP096'
  tag fix_id: 'F-48415r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001668']
  tag nist: ['SI-3 a']
end
