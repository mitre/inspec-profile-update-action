control 'SV-55460' do
  title 'The Symantec Endpoint Protection client Outlook Auto-Protect actions must be explicitly configured at the top, Malware, level and not be overridden by sub-levels.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and to not click hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses but are self-contained rather than being designed to infect an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Email Scans -> Select Microsoft Outlook Auto-Protect -> Select the Actions tab -> Under Actions -> Under Malware -> Select Virus -> Ensure "Override actions configured for Malware" is NOT selected.

Criteria:  If "Override actions configured for Malware" is selected, this is a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan\\Malware

Criteria:  If the value of FirstAction is not 5, this is a finding.
If the value of FirstAction is 5, then check A.  A must be compliant for the check to be not a finding.
A - If the value of OverrideDefaultActions within HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan\\TCID-0 is 0 or the value is not there, this is not a finding.

64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan\\Malware

Criteria:  If the value of FirstAction is not 5, this is a finding.
If the value of FirstAction is 5, then check A.  A must be compliant for the check to be not a finding.
A - If the value of OverrideDefaultActions within HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan\\Malware\\TCID-0 is 0 or the value is not there, this is not a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Email Scans -> Select  Microsoft Outlook Auto-Protect -> Select the Actions tab -> Under Actions -> Under Malware -> Select Virus -> Ensure "Override actions configured for Malware" is NOT selected.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-49004r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42732'
  tag rid: 'SV-55460r1_rule'
  tag stig_id: 'DTASEP077'
  tag gtitle: 'DTASEP077'
  tag fix_id: 'F-48318r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
