control 'SV-76859' do
  title 'When ColdFusion is configured in a clustered configuration, ColdFusion must be configured to write log records from the clustered system components into a system-wide log trail that can be correlated.'
  desc 'Log generation and log records can be generated from various components within the application server. The list of logged events is the set of events for which logs are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating log records (e.g., logable events, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked).

The events occurring must be time-correlated in order to conduct accurate forensic analysis. In addition, the correlation must meet certain tolerance criteria. For instance, DoD may define that the time stamps of different logged events must not differ by any amount greater than ten seconds. It is also acceptable for the application server to utilize an external logging tool that provides this capability.'
  desc 'check', 'Determine if ColdFusion is part of a clustered environment by accessing the "Instance Manager" and the "Cluster Manager" settings under the "Enterprise Manager" menu within the Administrator Console.

If ColdFusion is not setup in a clustered configuration, this finding is not applicable.

Ask the SA if a log record aggregation tool is being used to compile the log records from the ColdFusion application servers within the cluster for storage and review.

If the log records are not being aggregated, this is a finding.'
  desc 'fix', 'Implement a strategy to aggregate the log data from the ColdFusion application servers within the cluster for system-wide log trail storage and review.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63173r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62369'
  tag rid: 'SV-76859r1_rule'
  tag stig_id: 'CF11-02-000032'
  tag gtitle: 'SRG-APP-000086-AS-000048'
  tag fix_id: 'F-68289r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000174']
  tag nist: ['AU-12 (1)']
end
