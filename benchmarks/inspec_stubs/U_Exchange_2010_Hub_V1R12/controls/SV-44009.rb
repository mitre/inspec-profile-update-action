control 'SV-44009' do
  title 'Send Connector connections count must be limited.'
  desc 'This setting controls the maximum number of simultaneous outbound connections allowed for a given SMTP Connector, and can be used to throttle the SMTP service if resource constraints warrant it.  If the limit is too low, connections may be dropped.  If too high, some domains may use a disproportionate resource share, denying access to other domains.   Appropriate tuning reduces risk of data delay or loss.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the value for 'SMTP Server Maximum Outbound Connections'.

Open the Exchange Management Shell and enter the following command:

Get-TransportServer -Identity <'ServerUnderReview'> | Select Name, Identity, MaxOutboundConnections

If the value of 'MaxOutboundConnections' is set to 1000 this is not a finding.

If the value of 'MaxOutboundConnections' is set to a value other than 1000 and has signoff and risk acceptance in the EDSP, this is not a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-TransportServer -Identity <'ServerUnderReview'> -MaxOutboundConnections 1000.  

If an alternate value is desired, obtain signoff with risk acceptance and document in the EDSP."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41695r1_chk'
  tag severity: 'low'
  tag gid: 'V-33589'
  tag rid: 'SV-44009r1_rule'
  tag stig_id: 'Exch-2-760'
  tag gtitle: 'Exch-2-760'
  tag fix_id: 'F-37480r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
