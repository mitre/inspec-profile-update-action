control 'SV-16748' do
  title 'Virtual switch port group is configured to VLAN 4095.'
  desc 'The VLAN ID restricts port group traffic to a logical Ethernet segment within the physical network. Port groups may have a VLAN ID of 0 to 4095. VLAN IDs that have VLAN ID 4095 are able reach other port groups located on other VLANs. Basically, VLAN ID 4095 specifies that the port group should use trunk mode or VGT mode, which allows the guest operating system to manage its own VLAN tags. Guest operating systems typically do not manage their VLAN membership on networks. VLAN 1001 through 1024 are Cisco reserved VLANs. VLANs 1, 1001 to 1024, and 4095 will be not be used for virtual switch port groups since they may cause an unexpected operation.'
  desc 'check', '1. Log into VirtualCenter with the VI Client and select the ESX server from the inventory panel.
2. Click the Configuration tab and click Networking.
    Virtual switches are presented in a layout that shows an overview and details.
3. On the right side of the window, click Properties for a network.
4. Click the Ports tab.
5. In the Properties dialog box for the port group, click the General tab to check the VLAN ID.  If the VLAN ID is set to 4095, this is a finding.

Caveat: This check is Not Applicable if the number of VLANs needed for the virtual machine exceeds 4 VLANs, and it is documented with the IAO/SA.'
  desc 'fix', 'Do not configure virtual switch VLAN IDs s to be VLAN 1, 1001-1024, and 4095.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16051r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15809'
  tag rid: 'SV-16748r1_rule'
  tag stig_id: 'ESX0200'
  tag gtitle: 'Virtual switch port group is set to VLAN 4095.'
  tag fix_id: 'F-15753r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
