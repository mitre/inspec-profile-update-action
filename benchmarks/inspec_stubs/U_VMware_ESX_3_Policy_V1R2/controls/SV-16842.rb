control 'SV-16842' do
  title 'No policy exists to restrict copying and sharing virtual machines over networks and removable media.'
  desc 'As virtual machines replace real hardware they can undermine the security architecture of many organizations which often assume predictable and controlled change number of hosts, host configurations, host locations etc.  Some useful mechanisms that virtual machines provide are copying or sharing virtual machine hard disks. Copying or sharing virtual machine hard disks can be done over networks and removable media. Typically, test and development virtual machines will be moved and updated more frequently than production virtual machines. There will be a policy in place to restrict the copying and sharing of production virtual machines over networks and removable media to ensure that administrators do not give unauthorized users access to the virtual machine files.'
  desc 'check', 'Request a copy of the policy restricting virtual machine sharing and copying over networks and removable media.  If no policy exists, this is a finding.

Caveat: This is not applicable to snapshot backups, disaster recovery virtual machines, test and development virtual machines, and clustered virtual machines.'
  desc 'fix', 'Develop a policy that prohibits virtual machine sharing and copying over networks and removable media.'
  impact 0.3
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16260r1_chk'
  tag severity: 'low'
  tag gid: 'V-15900'
  tag rid: 'SV-16842r1_rule'
  tag stig_id: 'ESX1040'
  tag gtitle: 'No policy exists to restrict copying and sharing'
  tag fix_id: 'F-15861r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECSC-1'
end
