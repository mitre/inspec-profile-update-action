control 'SV-228387' do
  title 'The Exchange global inbound message size must be controlled.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. Message size limits should be set to 10 megabytes (MB) at most but often are smaller, depending on the organization. The key point in message size is that it should be set globally and should not be set to "unlimited". Selecting "unlimited" on "MaxReceiveSize" is likely to result in abuse and can contribute to excessive server disk space consumption. 

Message size limits may also be applied on SMTP connectors, Public Folders, and on the user account under Active Directory (AD). Changes at these lower levels are discouraged, as the single global setting is usually sufficient. This practice prevents conflicts that could impact availability and simplifies server administration.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP) or document that contains this information. 

Determine the global maximum message receive size. 

Open the Exchange Management Shell and enter the following command:

Get-TransportConfig | Select Name, Identity, MaxReceiveSize

If the value of "MaxReceiveSize" is not set to "10MB", this is a finding.

or

If "MaxReceiveSize" is set to an alternate value and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', 'Update the EDSP to specify the "MaxReceiveSize" value or verify that this information is documented by the organization.

Open the Exchange Management Shell and enter the following command:

Set-TransportConfig -MaxReceiveSize 10MB

or

Enter the value as identified by the EDSP that has obtained a signoff with risk acceptance.'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30620r496957_chk'
  tag severity: 'low'
  tag gid: 'V-228387'
  tag rid: 'SV-228387r879651_rule'
  tag stig_id: 'EX16-MB-000430'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-30605r496958_fix'
  tag 'documentable'
  tag legacy: ['SV-95399', 'V-80689']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
