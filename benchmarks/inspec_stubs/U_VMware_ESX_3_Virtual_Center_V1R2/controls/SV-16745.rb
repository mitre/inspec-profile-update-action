control 'SV-16745' do
  title 'Virtual machines are connected to public virtual switches and are not documented.'
  desc 'Public virtual switches are bound to physical NICs providing virtual machines connectivity to the physical network, whereas connecting physical servers to the LAN usually requires a cable. Virtual network configuration is much easier since once a virtual machine is attached to a virtual switch, these machines are able to send and receive packets. Care must be taken as to which virtual machines have access to the physical network through the public virtual switches. The master configuration file for virtual switches is the esx.conf file.'
  desc 'check', '1. Request the documentation for all virtual machines connected to public virtual switches.  If no documentation exists or the documentation is not accurate, this is a finding. 
2. Log into VirtualCenter with the VI Client, and select the ESX server from the inventory panel.
    The hardware configuration page for the server appears.
3. Click the Configuration tab, and click Networking.
4. Review all virtual switches that have virtual machines connected to them that may access the  external network. Compare the actual configuration to the documentation and verify that no discrepancies exist. If so, this is a finding.'
  desc 'fix', 'Document all virtual machines that need access to public virtual switches.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16029r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15806'
  tag rid: 'SV-16745r1_rule'
  tag stig_id: 'ESX0170'
  tag gtitle: 'No documentation for public virtual machines.'
  tag fix_id: 'F-15749r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECSC-1'
end
