control 'SV-55547' do
  title 'The Symantec Endpoint Protection client Outlook Auto-Protect actions must be explicitly configured at the top, Security Risks, level and not be overridden by the Remote Access sub-level.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and to not click hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses but are self-contained rather than being designed to infect an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Outlook Auto-Protect tab -> Select the Actions tab -> Under Security Risks -> Select Remote Access -> Ensure "Override actions configured for Security Risks" is NOT selected.

Criteria:  If "Override actions configured for Security Risks" is selected, this is a finding. 

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan\\Expanded

Criteria:  If the value of FirstAction is not 3, this is a finding.
If the value of FirstAction is 3, then check A. A must be compliant for the check to be not a finding.
A - If the value of OverrideDefaultActions within HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan}\\Expanded\\TCID-9 is 0 or the value is not there, this is not a finding.

64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan\\Expanded

Criteria:  If the value of FirstAction is not 3, this is a finding.
If the value of FirstAction is 3, then check A. A must be compliant for the check to be not a finding.
A - If the value of OverrideDefaultActions within HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan\\Expanded\\TCID-9 is 0 or the value is not there, this is not a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Outlook Auto-Protect tab -> Select the Actions tab -> Under Security Risks -> Select Remote Access -> Ensure "Override actions configured for Security Risks" is NOT selected.'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49091r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42819'
  tag rid: 'SV-55547r1_rule'
  tag stig_id: 'DTASEP086'
  tag gtitle: 'DTASEP086'
  tag fix_id: 'F-48405r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
