control 'SV-16792' do
  title 'There are no procedures for the backup and recovery of the ESX Server, management servers, and virtual machines.'
  desc 'Backup and recovery procedures are critical to the availability and protection of the virtual infrastructure. Availability of the system will be hindered if the system is compromised, shutdown, or not available. Backup and recovery of the virtual environment includes the ESX Servers, management servers, and virtual machines. The ESX Server has three major components required for backup and recovery. These components are virtual disks, virtual machine configuration files, and the configuration of the ESX Server itself. Due to the array of products and options available to backup the virtualization infrastructure, procedures will need to be developed to provide guidance to system administrators.'
  desc 'check', 'Request a copy of the backup and recovery procedures for the ESX Servers, management applications, and virtual machines.  If no procedures can be produced or they are incomplete, this is a finding.'
  desc 'fix', 'Develop backup and recovery procedures for the virtual infrastructure.'
  impact 0.3
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16200r1_chk'
  tag severity: 'low'
  tag gid: 'V-15851'
  tag rid: 'SV-16792r1_rule'
  tag stig_id: 'ESX0520'
  tag gtitle: "Backup and recovery procedures don't exist"
  tag fix_id: 'F-15805r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'DCSD-1'
end
