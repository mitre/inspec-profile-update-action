control 'SV-44055' do
  title 'Outbound Connection Limit per Domain Count must be controlled.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. This configuration controls the maximum number of simultaneous outbound connections from a domain, and works in conjunction with the Maximum Outbound Connections Count setting as a delivery tuning mechanism. If the limit is too low, connections may be dropped. If too high, some domains may use a disproportionate resource share, denying access to other domains. Appropriate tuning reduces risk of data delay or loss. 

By default, a limit of 20 simultaneous outbound connections from a domain should be sufficient. The value may be adjusted if justified by local site conditions.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the value for 'Maximum Domain Connections' and the server under review.  

Open the Exchange Management Shell and enter the following command:

Get-TransportServer -Identity 
<'ServerUnderReview'> | Select Name, Identity, MaxPerDomainOutboundConnections

If the value of 'MaxPerDomainOutboundConnections' is set to 20 this is not a finding.

If the value of 'MaxPerDomainOutboundConnections' is set to a value other than 20 and has signoff and risk acceptance in the EDSP, this is not a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-TransportServer -Identity <'ServerUnderReview'> -MaxPerDomainOutboundConnections 20

If an alternate value is desired, obtain signoff with risk acceptance and document in the EDSP."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41744r2_chk'
  tag severity: 'low'
  tag gid: 'V-33635'
  tag rid: 'SV-44055r2_rule'
  tag stig_id: 'Exch-2-201'
  tag gtitle: 'Exch-2-201'
  tag fix_id: 'F-37527r2_fix'
  tag 'documentable'
end
