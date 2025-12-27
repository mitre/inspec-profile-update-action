control 'SV-16749' do
  title 'Port groups are not configured with a network label.'
  desc 'Port Groups define how virtual machine connections are made through the virtual switch.  Port groups may be configured with bandwidth limitations and VLAN tagging policies for each member port. Multiple ports may be aggregated under port groups to provide a local point for virtual machines to connect to a network. The maximum number of port groups that may be configured on a virtual switch is 512. Each port group is identified by a network label and a VLAN ID.  Network labels identify the port groups with a name. These names are important since they serve as a functional descriptor for the port group. Without these descriptions, identifying port groups and their functions becomes difficult as the network becomes more complex.'
  desc 'check', '1. Log into VirtualCenter with the VI Client and select the ESX server from the inventory panel.
2. Click the Configuration tab and click Networking.
    Virtual switches are presented in a layout that shows an overview and details.
3. On the right side of the window, click Properties for a network.
4. Click the Ports tab.
5.  In the Properties dialog box for the port group, click the General tab to check the Network Label. If no Network Label is configured, this is a finding.'
  desc 'fix', 'Configure a network label for all virtual switches.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16053r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15810'
  tag rid: 'SV-16749r1_rule'
  tag stig_id: 'ESX0210'
  tag gtitle: 'Port groups do not have a network label.'
  tag fix_id: 'F-15754r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
