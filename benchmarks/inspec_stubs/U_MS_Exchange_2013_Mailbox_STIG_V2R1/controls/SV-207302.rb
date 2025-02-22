control 'SV-207302' do
  title 'Exchange Receive connectors must control the number of recipients per message.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. 

This configuration controls the maximum number of recipients who will receive a copy of a message at one time. This tunable value is related to throughput capacity and can enable the ability to optimize message delivery. 

Note: There are two types of default Receive connecters:
Client Servername: Accepts SMTP connections from all non-MAPI clients, such as POP and IMAP. As POP and IMAP are not authorized for use in DoD, these should not be present. Their default value for MaxRecipientsPerMessage is 200.
Default Servername: Accepts connections from other Hub Transport servers and any Edge Transport servers. Their default value for MaxRecipientsPerMessage is 5000.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP). 

Determine the Maximum Recipients per Message value.

Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, MaxRecipientsPerMessage

For each Receive connector, evaluate the MaxRecipientsPerMessage value.  

For each Receive connector, if the value of MaxRecipientsPerMessage is not set to 5000, this is a finding.

or

If the value of Maximum Recipients per Message is set to a value other than 5000 and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', "Update the EDSP.

Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -MaxRecipientsPerMessage 5000 

Note: The <IdentityName> value must be in quotes.

or 

The value as identified by the EDSP that has obtained a signoff with risk acceptance.

Repeat the procedure for each Receive connector."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7560r393419_chk'
  tag severity: 'low'
  tag gid: 'V-207302'
  tag rid: 'SV-207302r615936_rule'
  tag stig_id: 'EX13-MB-000180'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-7560r393420_fix'
  tag 'documentable'
  tag legacy: ['SV-84633', 'V-70011']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
