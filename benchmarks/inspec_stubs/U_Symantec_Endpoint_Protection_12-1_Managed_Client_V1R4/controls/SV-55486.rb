control 'SV-55486' do
  title 'The Symantec Endpoint Protection client Internet Email Auto-Protect must be configured to send a notification email to the IAO, IAM, and/or ePO administrator when a threatened email message is detected.'
  desc 'Email has become one of the most frequently used methods of spreading malware, through embedded HTML code and attachments. User awareness and training, warning users to not open suspicious emails or email attachments and to not click hyperlinks, etc. from unknown or known senders, will not fully protect from email-borne malware. Mass mailing worms are similar to email-borne viruses but are self-contained rather than being designed to infect an existing file. Protecting from email-borne viruses and mass mailing worms by scanning email upon delivery mitigates the risk of infection via email.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Email Scans -> Select Internet Email Auto-Protect -> Select the Notifications tab -> Under Email Notifications -> Ensure "Send email to others" is selected -> Select Others -> Ensure the IAO, IAM, and/or ePO administrator are listed.

Criteria: If "Send email to others" is not selected, this is a finding. 
If "Send email to others" is selected and the IAO, IAM, and/ or the ePO administrator email addresses are not listed, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\InternetMail\\RealTimeScan 
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\InternetMail\\RealTimeScan

Criteria:  If the value of NotifySelected is not 1, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Email Scans -> Select Internet Email Auto-Protect -> Select the Notifications tab -> Under Email Notifications -> Select "Send email to others" -> Select Others -> Add the IAO, IAM, and/or ePO administrator email addresses.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-49030r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42758'
  tag rid: 'SV-55486r1_rule'
  tag stig_id: 'DTASEP098'
  tag gtitle: 'DTASEP098'
  tag fix_id: 'F-48344r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001668']
  tag nist: ['SI-3 a']
end
