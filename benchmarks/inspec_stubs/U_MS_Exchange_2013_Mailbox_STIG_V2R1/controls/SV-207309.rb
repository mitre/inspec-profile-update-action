control 'SV-207309' do
  title 'The Exchange global inbound message size must be controlled.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. Message size limits should be set to 10 megabytes at most, but often are smaller, depending on the organization. The key point in message size is that it should be set globally and should not be set to "unlimited". Selecting "unlimited" on either field is likely to result in abuse and can contribute to excessive server disk space consumption. 

Message size limits may also be applied on SMTP connectors, Public Folders, and on the user account under AD. Changes at these lower levels are discouraged, as the single global setting is usually sufficient. This practice prevents conflicts that could impact availability and simplifies server administration.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the global maximum message receive size. 

Open the Exchange Management Shell and enter the following command:

Get-TransportConfig | Select Name, Identity, MaxReceiveSize

If the value of MaxReceiveSize is not set to 10MB, this is a finding.

or

If the value of MaxReceiveSize is set to an alternate value and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', 'Update the EDSP.

Open the Exchange Management Shell and enter the following command:

Set-TransportConfig -MaxReceiveSize 10MB

or

The value as identified by the EDSP that has obtained a signoff with risk acceptance.'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7567r393440_chk'
  tag severity: 'low'
  tag gid: 'V-207309'
  tag rid: 'SV-207309r615936_rule'
  tag stig_id: 'EX13-MB-000215'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-7567r393441_fix'
  tag 'documentable'
  tag legacy: ['SV-84647', 'V-70025']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
