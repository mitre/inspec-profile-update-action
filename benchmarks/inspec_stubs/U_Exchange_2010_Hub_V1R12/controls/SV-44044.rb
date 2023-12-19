control 'SV-44044' do
  title 'Global inbound message size must be controlled.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. Message size limits should be set to 10 megabytes at most, but often are smaller, depending on the organization. The key point in message size is that it should be set globally, and it should not be set to ‘unlimited’.   Selecting ‘unlimited’ on either field is likely to result in abuse and can contribute to excessive server disk space consumption. 

Message size limits may also be applied on SMTP connectors, Public Folders, and on the user account under AD.  Changes at these lower levels are discouraged, as the single global setting is usually sufficient. This practice prevents conflicts that could impact availability and it simplifies server administration.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the global maximum message receive size. 

Open the Exchange Management Shell and enter the following command:
Get-TransportConfig | Select Identity, MaxReceiveSize

If the value of 'MaxReceiveSize' is set to 10MB, this is not a finding.

If the value of 'MaxReceiveSize' is set to an alternate value, and has signoff and risk acceptance in the EDSP, this is not a finding.

If the value of 'MaxReceiveSize' is set to “Unlimited”, this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-TransportConfig  -MaxReceiveSize 10MB

If an alternate value is desired, obtain signoff with risk acceptance and document in the EDSP.'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41731r1_chk'
  tag severity: 'low'
  tag gid: 'V-33624'
  tag rid: 'SV-44044r1_rule'
  tag stig_id: 'Exch-2-011'
  tag gtitle: 'Exch-2-011'
  tag fix_id: 'F-37516r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
