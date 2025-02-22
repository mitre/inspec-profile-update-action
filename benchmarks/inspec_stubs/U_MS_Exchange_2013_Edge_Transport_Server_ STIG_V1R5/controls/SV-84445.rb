control 'SV-84445' do
  title 'Exchange Global Outbound Message size must be controlled.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. Message size limits should be set to 10 megabytes at most but often are smaller, depending on the organization. The key point in message size is that it should be set globally, and it should not be set to "unlimited". Selecting "unlimited" on either field is likely to result in abuse and can contribute to excessive server disk space consumption. 

Message size limits may also be applied on Send and Receive connectors, public folders, and the user account in Active Directory. Changes at these lower levels are discouraged, as the single global setting is usually sufficient. This practice prevents conflicts that could impact availability and simplifies server administration.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the global maximum message send size. 

Open the Exchange Management Shell and enter the following command:

Get-TransportConfig | Select Name, Identity, MaxSendSize

If the value of MaxSendSize is not set to 10MB, this is a finding.

or

If the value of MaxSendSize is set to an alternate value and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', 'Update the EDSP.

Open the Exchange Management Shell and enter the following command:

Set-TransportConfig -MaxSendSize 10MB

or

The value as identified by the EDSP that has obtained a signoff with risk acceptance.'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70293r1_chk'
  tag severity: 'low'
  tag gid: 'V-69823'
  tag rid: 'SV-84445r1_rule'
  tag stig_id: 'EX13-EG-000105'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-76053r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
