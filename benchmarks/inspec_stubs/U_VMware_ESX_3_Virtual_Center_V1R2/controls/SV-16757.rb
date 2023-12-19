control 'SV-16757' do
  title 'Promiscuous Mode is set to “Accept” on virtual switches.'
  desc 'ESX Server has the ability to run virtual and physical network adapters in promiscuous mode. Promiscuous mode may be enabled on public and private virtual switches. When promiscuous mode is enabled for a public virtual switch, all virtual machines connected to the public virtual switch have the potential of reading all packets sent across that network, from other virtual machines and any physical machines or other network devices. When promiscuous mode is enabled for a private virtual switch, all virtual machines connected to the private virtual switch have the potential of reading all packets across that network, meaning only the virtual machines connected to that private virtual switch. By default, promiscuous mode is set to Reject, meaning that the virtual network adapter cannot operate in Promiscuous mode.  

Promiscuous mode will be disabled on the ESX Server virtual switches since confidential data may be revealed while in this mode. Promiscuous mode is disabled by default on the ESX Server; however there might be a legitimate reason to enable it for debugging, monitoring, or troubleshooting reasons.  To enable promiscuous mode for a virtual switch, a value is inserted into a special virtual file in the /proc file system.'
  desc 'check', '1. Log into VirtualCenter with the VI Client and select the ESX server from the inventory panel.
    The hardware configuration page for the server appears.
2. Click the Configuration tab, and click Networking.
3. Click Properties for the virtual switch whose layer 2 policy you want to review.
4. In the Properties dialog box for the virtual switch, click the Ports tab.
5. Select the virtual switch item and click Edit.
6. In the Properties dialog box for the virtual switch, click the Security tab.
7. Verify the Promiscuous Mode is set to Reject. If it is not, this is a finding.

Note: If promiscuous mode is turned on for troubleshooting purposes, then it must be documented and approved with the IAO/SA.'
  desc 'fix', 'Configure the Promiscuous Mode Policy to “Reject".'
  impact 0.7
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16108r1_chk'
  tag severity: 'high'
  tag gid: 'V-15818'
  tag rid: 'SV-16757r1_rule'
  tag stig_id: 'ESX0270'
  tag gtitle: 'Promiscuous Mode is set to "Accept".'
  tag fix_id: 'F-15770r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
