control 'SV-55461' do
  title 'The Symantec Endpoint Protection client Outlook Auto-Protect actions for when Malware has been detected must be configured to Clean Risk as first action.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and to not click hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses but are self-contained rather than being designed to infect an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Email Scans -> Select Microsoft Outlook Auto-Protect -> Select the Actions tab -> Under Actions -> Select Malware -> Observe the First action and the If first action fails boxes -> Ensure First action is set to "Clean Risk". 

Criteria:  If First action is not set to "Clean Risk", this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan\\Malware
64 bit: 
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan\\Malware

Criteria:  If the value of "FirstAction" is 5, this is not a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings,  Email Scans -> Select Microsoft Outlook Auto-Protect -> Select the Actions tab -> Under Actions -> Select Malware -> Observe the First action and the If first action fails boxes -> Set First action to "Clean Risk".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-49005r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42733'
  tag rid: 'SV-55461r1_rule'
  tag stig_id: 'DTASEP078'
  tag gtitle: 'DTASEP078'
  tag fix_id: 'F-48319r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
