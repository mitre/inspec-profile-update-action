control 'SV-228383' do
  title 'Exchange Receive connectors must control the number of recipients per message.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. 

This configuration controls the maximum number of recipients who will receive a copy of a message at one time. This tunable value is related to throughput capacity and can enable the ability to optimize message delivery. 

Note: There are two types of default Receive connecters:

Client Servername: Accepts SMTP connections from all non-MAPI clients, such as POP and IMAP. As POP and IMAP are not authorized for use in DoD, these should not be present. Their default value for "MaxRecipientsPerMessage" is "200".

Default Servername: Accepts connections from other Hub Transport servers and any Edge Transport servers. Their default value for "MaxRecipientsPerMessage" is "5000".'
  desc 'check', 'Note: This requirement applies to IMAP4. IMAP Secure is not restricted and does not apply to this requirement.

Review the Email Domain Security Plan (EDSP) or document that contains this information. 

Determine the Maximum Recipients per Message value.

Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, MaxRecipientsPerMessage

For each Receive connector, evaluate the "MaxRecipientsPerMessage" value.

For each Receive connector, if the value of "MaxRecipientsPerMessage" is not set to "5000", this is a finding.

or

If the value of "MaxRecipientsPerMessage" is set to a value other than "5000" and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', %q(Update the EDSP to specify the "MaxRecipientsPerMessage" value or verify that this information is documented by the organization.

Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -MaxRecipientsPerMessage 5000 

Note: The <IdentityName> value must be in single quotes.

or 

Enter the value as identified by the EDSP that has obtained a signoff with risk acceptance.

Repeat the procedure for each Receive connector.)
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30616r572120_chk'
  tag severity: 'low'
  tag gid: 'V-228383'
  tag rid: 'SV-228383r879651_rule'
  tag stig_id: 'EX16-MB-000360'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-30601r496946_fix'
  tag 'documentable'
  tag legacy: ['SV-95391', 'V-80681']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
