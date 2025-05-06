control 'SV-43992' do
  title 'Receive Connectors must control the number of recipients per message.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. 

This configuration controls the maximum number of recipients who will receive a copy of a message at one time.  This tunable value is related to throughput capacity and can enable the ability to optimize message delivery. 

Note: There are two types of default Receive Connecters:
Client Servername: This Receive connector accepts SMTP connections from all non-MAPI clients, such as POP and IMAP. As POP and IMAP are not authorized for use in DoD, these should not be present. Their default value for MaxRecipientsPerMessage is 200.
Default Servername: This Receive connector accepts connections from other Hub Transport servers and any Edge Transport servers. Their default value for MaxRecipientsPerMessage is 5000.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the 'Maximum Recipients per Message' value:

Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, MaxRecipientsPerMessage

For each receive connector, evaluate the 'MaxRecipientsPerMessage' value.  

If the value of 'Maximum Recipients per Message' is set to a value other than 5000, and has signoff and risk acceptance in the EDSP, this is not a finding.

If the value of 'MaxRecipientsPerMessage' is not set to 5000, this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'ReceiveConnector'> -MaxRecipientsPerMessage 5000 or other value as identified by the EDSP."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41678r2_chk'
  tag severity: 'low'
  tag gid: 'V-33572'
  tag rid: 'SV-43992r2_rule'
  tag stig_id: 'Exch-2-727'
  tag gtitle: 'Exch-2-727'
  tag fix_id: 'F-37463r2_fix'
  tag 'documentable'
end
