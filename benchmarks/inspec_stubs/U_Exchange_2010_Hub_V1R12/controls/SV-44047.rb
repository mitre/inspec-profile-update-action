control 'SV-44047' do
  title 'Global outbound message size must be controlled.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. Message size limits should be set to 10 megabytes at most, but often are smaller, depending on the organization. The key point in message size is that it should be set globally, and it should not be set to ‘unlimited’.   Selecting ‘unlimited’ on either field is likely to result in abuse and can contribute to excessive server disk space consumption. 

Message size limits may also be applied on send and receive connectors, Public Folders, and on the user account under AD. Changes at these lower levels are discouraged, as the single global setting is usually sufficient. This practice prevents conflicts that could impact availability and it simplifies server administration.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the global maximum message send size. 

Open the Exchange Management Shell and enter the following command:
Get-TransportConfig | Select Identity, MaxSendSize

If the value of 'MaxSendSize' is set to 10MB, this is not a finding.

If the value of 'MaxSendSize' is set to an alternate value, and has signoff and risk acceptance in the EDSP, this is not a finding.

If the value of 'MaxSendSize' is set to “Unlimited”, this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-TransportConfig  -MaxSendSize 10MB

If an alternate value is desired, obtain signoff with risk acceptance and document in the EDSP.'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41735r1_chk'
  tag severity: 'low'
  tag gid: 'V-33627'
  tag rid: 'SV-44047r2_rule'
  tag stig_id: 'Exch-2-015'
  tag gtitle: 'Exch-2-015'
  tag fix_id: 'F-37519r1_fix'
  tag 'documentable'
end
