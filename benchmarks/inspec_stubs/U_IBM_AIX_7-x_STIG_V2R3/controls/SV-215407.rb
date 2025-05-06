control 'SV-215407' do
  title 'In the event of a system failure, AIX must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. 

Preserving operating system state information helps to facilitate operating system restart and return to the operational mode of the organization with least disruption to mission/business processes.'
  desc 'check', 'To display the current dump device settings enter the following command:
#sysdumpdev -l
 
primary              /dev/lg_dumplv
secondary            /dev/sysdumpnull
copy directory       /var/adm/ras
forced copy flag     TRUE
always allow dump    FALSE
dump compression     ON
type of dump         fw-assisted
full memory dump     disallow

If the primary device and copy directory is not configured, this is a finding.'
  desc 'fix', 'The "sysdumpdev" command should be used to configure dump device.

#sysdumpdev -p "Primary dump device"
#sysdumpdev -d  <directory>

Note: The "-d <directory> " specifies the directory the device is copied to at boot time.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16605r294672_chk'
  tag severity: 'medium'
  tag gid: 'V-215407'
  tag rid: 'SV-215407r508663_rule'
  tag stig_id: 'AIX7-00-003109'
  tag gtitle: 'SRG-OS-000269-GPOS-00103'
  tag fix_id: 'F-16603r294673_fix'
  tag 'documentable'
  tag legacy: ['V-91487', 'SV-101585']
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
