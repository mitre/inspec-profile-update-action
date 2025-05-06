control 'SV-16831' do
  title 'Nonpersistent disk mode is set for virtual machines.'
  desc 'The security issue with nonpersistent disk mode is that attackers may undo or remove any traces that they were ever on the machine with a simple shutdown or reboot. Once the virtual machine has been shutdown, the vulnerability used to access the virtual machine will still be present, and the attacker may access the virtual machine in the future at a point in time of their choice. The danger is that administrators may never know if they have been attacked or hacked. To safeguard against this, nonpersistent disk mode will be only used for test and development virtual machines. Production virtual machines will be set to persistent disk mode only.'
  desc 'check', 'Pick one or two virtual machines to verify for compliance.
1. Log into the VirtualCenter Server with the VI Client and select the server from the inventory panel.
    The hardware configuration page for the server appears.
2. Expand the inventory as needed, and select the virtual machine that you would like to check. 3. Click the Edit Settings link in the Commands panel to display the Virtual Machine Properties dialog box.   
4. Select the Hardware tab.
5. Click the appropriate Hard Disk in Hardware list, and verify that Nonpersistent mode is not selected.  If nonpersistent mode is selected, this is a finding.

Caveat: Nonpersistent disk mode may be used if it has been documented and approved by the DAA.'
  desc 'fix', 'Configure all virtual machines to use persistent disk mode only, which is the default.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16249r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15890'
  tag rid: 'SV-16831r1_rule'
  tag stig_id: 'ESX0940'
  tag gtitle: 'Nonpersistent disk mode is set for VMs.'
  tag fix_id: 'F-15850r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
end
