control 'SV-16841' do
  title 'Test and development virtual machines are not logically separated from production virtual machines.'
  desc 'Test and development can be defined by using the folllowing definitions from the Enclave STIG.  Testing is a process of technical investigation intended to reveal quality-related information about
the product with respect to the context in which it is intended to operate. This includes, but is not limited to, the process of executing a program or application with the intent of finding errors. Development is the process by which something passes by degrees to a different stage.

Test and development virtual machines will be logically separated from the production virtual machines. Logically separating test and development virtual machines ensures that any test and development traffic does not traverse the production LAN. This separation applies to Zone A and B only as referenced the Enclave STIG.  Zone C and D should be completely isolated from any production network.  This traffic separation will enhance the availability of the production servers. The preferred logical configuration is for the test and development VLAN to be assigned a dedicated physical network adapter on the ESX Server. If this is not feasible, then a separate VLAN on the production physical network adapter is acceptable.'
  desc 'check', 'Ask the IAO/SA if test and development virtual machines are are configured on the same ESX Server farm as production virtual machines.  If the answer is "No", then this is not applicable.  If the answer is "Yes", then ask what type of zone the test and development virtual machines are in?  If they are in Zone A or B, then proceed to step 1.  If they are in Zone C or D, this is a finding.  
1. Log into VirtualCenter with the VI Client and select the server from the inventory panel.
The hardware configuration page for this server appears.
2. Click the Configuration tab, and click Networking.  
3. Examine the virtual switches and their respective VLAN IDs.  A separate and dedicated VLAN ID should be configured for test and development virtual machines. If there is no VLAN ID defined for test and development virtual machines, this is a finding.'
  desc 'fix', 'Assign a dedicated VLAN ID for all test and development virtual machines in Zone A and B as referenced in the Enclave STIG.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16259r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15899'
  tag rid: 'SV-16841r1_rule'
  tag stig_id: 'ESX1030'
  tag gtitle: 'T&D virtual machines are separated from production'
  tag fix_id: 'F-15860r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
end
