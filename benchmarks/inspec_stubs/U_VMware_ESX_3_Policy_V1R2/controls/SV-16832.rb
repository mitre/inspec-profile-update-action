control 'SV-16832' do
  title 'No policy exists to assign virtual machines to personnel.'
  desc 'In traditional computing environments, servers were usually assigned to various personnel for administration. For instance, the data server is administered by the database administrator; the domain controller is maintained by the network administrator, etc. Other methods include assigning the MAC address to specific personnel or identifying machines by Ethernet location or port number. All these approaches are impractical in the virtual machine environment.

In the virtual environment, virtual machines may be moved or have MAC addresses that may change. These scenarios make it difficult to establish who owns the virtual machine running on a particular host. Therefore, a policy will need to be implemented to identify and assign virtual machines to the appropriate personnel.'
  desc 'check', 'Request a copy of the policy that is used to assign virtual machines to personnel.  If no policy or procedure exists, this is a finding.'
  desc 'fix', 'Develop a policy for assigning virtual machines to the appropriate personnel.'
  impact 0.3
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16250r1_chk'
  tag severity: 'low'
  tag gid: 'V-15891'
  tag rid: 'SV-16832r1_rule'
  tag stig_id: 'ESX0950'
  tag gtitle: 'No policy exists to assign virtual machines'
  tag fix_id: 'F-15851r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECSC-1'
end
