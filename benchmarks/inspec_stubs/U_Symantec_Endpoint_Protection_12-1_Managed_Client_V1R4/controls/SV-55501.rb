control 'SV-55501' do
  title 'The Symantec Endpoint Protection client Internet Email Auto-Protect actions for when a security risk has been detected must be configured to Delete Risk as first action.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and to not click hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses but are self-contained rather than being designed to infect an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Email Scans -> Select Internet Email Auto-Protect -> Select the Actions tab -> Under Actions -> Select Security Risks -> Observe the First action and the If first action fails boxes -> Ensure First action is set to "Delete Risk". 

Criteria:  If First action is not set to "Delete Risk", this is a finding.

On the client machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\InternetMail\\RealTimeScan\\Expanded
64 bit: 
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\InternetMail\\RealTimeScan\\Expanded

Criteria:  If the value of "FirstAction" is not 3, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Email Scans -> Select Internet Email Auto-Protect -> Select the Actions tab -> Under Actions -> Select Security Risks -> Observe the First action and the If first action fails boxes -> Set First action to "Delete Risk".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-49045r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42773'
  tag rid: 'SV-55501r1_rule'
  tag stig_id: 'DTASEP113'
  tag gtitle: 'DTASEP113'
  tag fix_id: 'F-48359r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001668']
  tag nist: ['SI-3 a']
end
