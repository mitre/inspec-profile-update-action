control 'SV-228398' do
  title 'The Exchange Global Recipient Count Limit must be set.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. The Global Recipient Count Limit field is used to control the maximum number of recipients that can be specified in a single message sent from this server. Its primary purpose is to minimize the chance of an internal sender spamming other recipients, since spam messages often have a large number of recipients. Spam prevention can originate from both outside and inside organizations. While inbound spam is evaluated as it arrives, controls such as this one help prevent spam that might originate inside the organization. 

The Recipient Count Limit is global to the Exchange implementation. Lower-level refinements are possible; however, in this configuration strategy, setting the value once at the global level facilitates a more available system by eliminating potential conflicts among multiple settings. A value of less than or equal to "5000" is probably larger than is needed for most organizations but is small enough to minimize usefulness to spammers and is easily handled by Exchange. An unexpanded distribution is handled as one recipient. Specifying "unlimited" may result in abuse.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the global maximum message recipient count. 

Open the Exchange Management Shell and enter the following command:

Get-TransportConfig | Select Name, Identity, MaxRecipientEnvelopeLimit

If the value of "MaxRecipientEnvelopeLimit" is not set to "5000", this is a finding.

or

If "MaxRecipientEnvelopeLimit" is set to an alternate value and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', 'Update the EDSP to specify the global maximum message recipient count.

Set-TransportConfig -MaxRecipientEnvelopeLimit 5000

or

Enter the value as identified by the EDSP that has obtained a signoff with risk acceptance.

Restart the Microsoft Exchange Information Store service.'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30631r496990_chk'
  tag severity: 'low'
  tag gid: 'V-228398'
  tag rid: 'SV-228398r879653_rule'
  tag stig_id: 'EX16-MB-000540'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-30616r496991_fix'
  tag 'documentable'
  tag legacy: ['SV-95421', 'V-80711']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
