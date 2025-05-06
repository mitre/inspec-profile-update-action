control 'SV-55498' do
  title 'The Symantec Endpoint Protection client Internet Email Auto-Protect actions must be explicitly configured at the top, Security Risks, level and not be overridden by the Security Risk sub-level.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and to not click hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses but are self-contained rather than being designed to infect an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Email Scans -> Select Internet Email Auto-Protect -> Select the Actions tab -> Under Actions -> Under Security Risks -> Select Security Risk -> Ensure "Override actions configured for Security Risks" is NOT selected.

Criteria:  If "Override actions configured for Security Risks" is selected, this is a finding.

On the client machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\InternetMail\\RealTimeScan\\Expanded

Criteria:  If the value of FirstAction is not 3, this is a finding.
If the value of FirstAction is 3, then check A. A must be compliant for the check to be not a finding.
A - If the value of OverrideDefaultActions within HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\InternetMail\\RealTimeScan\\Expanded\\TCID-4 is 0 or the value is not there, this is not a finding.

64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\InternetMail\\RealTimeScan\\Expanded

Criteria:  If the value of FirstAction is not 3, this is a finding.
If the value of FirstAction is 3, then check A. A must be compliant for the check to be not a finding.
A - If the value of OverrideDefaultActions within HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\InternetMail\\RealTimeScan\\Expanded\\TCID-4 is 0 or the value is not there, this is not a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Email Scans -> Select Internet Email Auto-Protect -> Select the Actions tab -> Under Actions -> Under Security Risks -> Select Security Risk -> Ensure "Override actions configured for Security Risks" is NOT selected.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-49042r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42770'
  tag rid: 'SV-55498r1_rule'
  tag stig_id: 'DTASEP110'
  tag gtitle: 'DTASEP110'
  tag fix_id: 'F-48356r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001668']
  tag nist: ['SI-3 a']
end
