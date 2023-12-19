control 'SV-223351' do
  title 'The junk email protection level must be set to No Automatic Filtering.'
  desc %q(This policy setting controls the Junk E-mail protection level. The Junk E-mail Filter in Outlook helps to prevent junk email messages, also known as spam, from cluttering a user's Inbox. The filter evaluates each incoming message based on several factors, including the time when the message was sent and the content of the message. The filter does not single out any particular sender or message type, but instead analyzes each message based on its content and structure to determine if it is likely spam.

A Junk E-mail filtering option of "No Automatic Filtering" will evaluate emails against domain names and email addresses in the blocked sender list and send them to the Junk E-mail folder. 

A Junk E-mail filtering option of "High" is not recommended when behind enterprise-level capabilities such as Enterprise Email Security Gateway (EEMSG), Cloud-Based Internet Isolation (CBII), and O365 Exchange Online Protection (EOP).)
  desc 'check', 'Note: If the Outlook client application is not used to access Office 365 email (i.e., email is only accessed via Outlook Web Access [OWA]), this check is not applicable.  

Verify Outlook Junk E-mail protection is set to "No Automatic Filtering".

In Outlook, click Home tab >> Delete group >> Junk >> Junk E-mail Options.

Verify Junk E-mail protection is set to "No Automatic Filtering".
 
If the system being inspected is not behind EEMSG, CBII, or O365 EOP, the Junk E-mail protection level must be set to "High".

If Junk E-mail protection is not set to "No Automatic Filtering", this is a finding.

If the system is not behind enterprise-level capabilities such as EEMSG, CBII, or O365 EOP and the Junk E-mail protection is not set to "High", this is a  finding.'
  desc 'fix', 'In Outlook, click Home tab >> Delete group >> Junk >> Junk E-mail Options.

Set the Junk E-mail protection level to "No Automatic Filtering".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25024r922085_chk'
  tag severity: 'medium'
  tag gid: 'V-223351'
  tag rid: 'SV-223351r922087_rule'
  tag stig_id: 'O365-OU-000006'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-25012r922086_fix'
  tag 'documentable'
  tag legacy: ['SV-108881', 'V-99777']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
