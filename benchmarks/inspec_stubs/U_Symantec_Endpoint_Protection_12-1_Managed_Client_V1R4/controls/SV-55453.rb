control 'SV-55453' do
  title 'The Symantec Endpoint Protection client Outlook Auto-Protect client must be enabled.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and to not click hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses but are self-contained rather than being designed to infect an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Email Scans -> Select Microsoft Outlook Auto-Protect -> Select the Scan Details tab -> Ensure "Enable Microsoft Outlook Auto-Protect" is selected.

Criteria:  If "Enable Microsoft Outlook Auto-Protect" is not selected, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan

Criteria:  If the value of OnOff is not 1, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Email Scans -> Select Microsoft Outlook Auto-Protect -> Select the Scan Details tab -> Select "Enable Microsoft Outlook Auto-Protect".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48997r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42725'
  tag rid: 'SV-55453r1_rule'
  tag stig_id: 'DTASEP071'
  tag gtitle: 'DTASEP071'
  tag fix_id: 'F-48311r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001668']
  tag nist: ['SI-3 a']
end
