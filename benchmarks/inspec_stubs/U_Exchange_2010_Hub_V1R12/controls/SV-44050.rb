control 'SV-44050' do
  title 'Global recipient count limit must be set.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. The Global Recipient Count limit field is used to control the maximum number of recipients that can be specified in a single message sent from this server. Its primary purpose is to minimize the chance of an internal sender spamming other recipients, since SPAM messages often have a large number of recipients. SPAM prevention can originate from both outside and inside organizations. While inbound SPAM is evaluated as it arrives, controls such as this one help prevent SPAM that might originate inside the organization. 

The Recipient Count Limit is global to the Exchange implementation. Lower-level refinements are possible; however, in this configuration strategy, setting the value once at the global level ensures a more available system by eliminating potential conflicts among multiple settings. A value of less than or equal to 5000 is probably larger than is needed for most organizations, but is small enough to minimize usefulness to spammers, and is easily handled by Exchange.  An unexpanded distribution is handled as one recipient.  Specifying “unlimited” may result in abuse.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the global maximum message recipient count. 

Open the Exchange Management Shell and enter the following command:

Get-TransportConfig | Select Identity, MaxRecipientEnvelopeLimit
If the value of 'MaxRecipientEnvelopeLimit' is set to 5000, this is not a finding.

If the value of 'MaxRecipientEnvelopeLimit' value is set to an alternate value, and has signoff and risk acceptance in the EDSP, this is not a finding.

If the value of 'MaxRecipientEnvelopeLimit' is set to 'Unlimited', this is a finding."
  desc 'fix', "Set-transportConfig  -'MaxRecipientEnvelopeLimit' 5000

Restart the “Microsoft Exchange Information Store” service.  

If an alternate value is desired, obtain signoff with risk acceptance and document in the EDSP."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41736r1_chk'
  tag severity: 'low'
  tag gid: 'V-33630'
  tag rid: 'SV-44050r1_rule'
  tag stig_id: 'Exch-2-017'
  tag gtitle: 'Exch-2-017'
  tag fix_id: 'F-37522r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
