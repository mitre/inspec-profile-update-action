control 'SV-237202' do
  title 'ColdFusion must provide a clustering capability.'
  desc 'Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. When application failure is encountered, preserving application state facilitates application restart and return to the operational mode of the organization with less disruption of mission/business processes.

Clustering of multiple ColdFusion servers is a common approach to providing fail-safe application availability when the system criticality requires redundancy.'
  desc 'check', 'This requirement is dependent upon system mission criticality.

If the system is not mission critical and does not require redundancy, this finding is not applicable.

Within the Administrator Console, navigate to the "Cluster Manager" under the "Enterprise Manager" menu.  Verify that there are configured clusters with more than 1 server in each cluster.

If there are no clusters defined or there is only one server in the cluster, this is a finding.'
  desc 'fix', 'Navigate to the "Cluster Manager" under the "Enterprise Manager" menu.  Create a cluster by defining a name and adding it to the configured clusters.  Edit the cluster to add available servers to the cluster and submit the changes to the cluster.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40421r641699_chk'
  tag severity: 'medium'
  tag gid: 'V-237202'
  tag rid: 'SV-237202r641701_rule'
  tag stig_id: 'CF11-05-000173'
  tag gtitle: 'SRG-APP-000225-AS-000154'
  tag fix_id: 'F-40384r641700_fix'
  tag 'documentable'
  tag legacy: ['SV-76967', 'V-62477']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
