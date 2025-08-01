control 'SV-16840' do
  title 'The IAO/SA does not document and approve virtual machine renames.'
  desc 'It may become necessary to rename a virtual machine at some point during the course of testing to production. To rename a virtual machine, the virtual machine must be powered down before proceeding with the renaming feature. It is also good practice to backup virtual machines before renaming any virtual machine. The configuration files for VMware are typically located on the service console in /root/VMware/ directory, and the virtual disks will be in the /vmfs/ directory.  Renaming virtual machines may cause communication issues on the network with other servers, users, etc.  To prevent communication disruptions to the network or virtual machine, all virtual machine renames will be documented and approved by the change control board.'
  desc 'check', 'Request a copy of the virtual machine rename approval documentation from the IAO/SA.  If no documentation can be produced, this is a finding.'
  desc 'fix', 'Develop approval documentation for all virtual machine renames.'
  impact 0.3
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16258r1_chk'
  tag severity: 'low'
  tag gid: 'V-15898'
  tag rid: 'SV-16840r1_rule'
  tag stig_id: 'ESX1020'
  tag gtitle: "IAO/SA doesn't document and approve renames"
  tag fix_id: 'F-15859r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECSC-1'
end
