control 'SV-16805' do
  title 'VirtualCenter virtual machine is not configured in an ESX Server cluster with High Availability enabled.'
  desc 'If the ESX Server hosting the VirtualCenter virtual machine fails, the single point of central administration to the entire virtual infrastructure is gone. To mitigate this potential scenario, High Availability (HA) will be configured through VMware HA. If one ESX Server host fails within a VMware HA cluster, another ESX Server will restart the VirtualCenter virtual machine.'
  desc 'check', '1. Log into the VirtualCenter Server with the VI Client.
2. Verify that there is a cluster configured by reviewing the inventory panel.  If no cluster is  configured, this is a finding.
3. Select the cluster and choose Edit Settings from the right-click menu.
4. In the Cluster Settings dialog box, verify Enable VMware HA is selected.  If it is not selected, this is a finding.'
  desc 'fix', 'Enable High Availability on ESX Server clusters for all VirtualCenter virtual machines.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16221r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15864'
  tag rid: 'SV-16805r1_rule'
  tag stig_id: 'ESX0650'
  tag gtitle: 'VirtualCenter virtual machine does not have HA.'
  tag fix_id: 'F-15824r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
