control 'SV-237204' do
  title 'ColdFusion, when part of a mission critical system, must be in a high-availability (HA) cluster.'
  desc "A mission critical system is a system that handles data vital to the organization's operational readiness or effectiveness of deployed or contingency forces.  A mission critical system must maintain the highest level of integrity and availability.  By High Availability (HA) clustering the ColdFusion application server, the hosted application and data are given a platform that is load-balanced and provides high-availability.  Most HA clusters consist of two nodes, which is the minimum required for redundancy, but HA clusters can consist of many more nodes.

ColdFusion does offer a clustering capability that must be used when the ColdFusion application server is part of a mission critical system."
  desc 'check', 'If ColdFusion is not part of a mission critical system, this requirement is not applicable.

Within the Administrator Console, navigate to the "Instance Manager" page under the "Enterprise Manager" menu.  Validate that two or more servers have been defined and that the servers are on different hosts.

If there are fewer than two servers available or the servers are on the same host, this is a finding.

Navigate to the "Cluster Manager" page under the "Enterprise Manager" menu.

If there are no clusters defined or any cluster has fewer than two servers in the cluster, this is a finding.'
  desc 'fix', 'If ColdFusion is not part of a mission critical system, this requirement is not applicable.

Within the Administrator Console, navigate to the "Instance Manager" page under the "Enterprise Manager" menu.  Define two or more servers to be part of each cluster.  Once the servers are defined for the cluster(s), navigate to the "Cluster Manager" page under the "Enterprise Manager" menu.  Define clusters for your mission critical ColdFusion installation.  Each defined cluster must contain two or more servers.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40423r641705_chk'
  tag severity: 'medium'
  tag gid: 'V-237204'
  tag rid: 'SV-237204r641707_rule'
  tag stig_id: 'CF11-05-000181'
  tag gtitle: 'SRG-APP-000435-AS-000069'
  tag fix_id: 'F-40386r641706_fix'
  tag 'documentable'
  tag legacy: ['SV-76971', 'V-62481']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
