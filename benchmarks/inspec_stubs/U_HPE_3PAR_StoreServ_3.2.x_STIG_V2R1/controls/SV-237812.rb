control 'SV-237812' do
  title 'The storage system must be operated at the latest maintenance update available from the vendor.'
  desc 'The organization must install security-relevant updates (e.g., patches, maintenance updates, and version updates). Due to the potential need for isolation of the storage system from automatic update mechanisms, the organization must give careful consideration to the methodology used to carry out updates.'
  desc 'check', "Determine when the last update occurred, by entering the following command:

cli% showpatch -hist

The output fields are 
InstallTime Id Package Version

Examine the InstallTime of the last entry in the output. 

If the last update occurred more than 3 months ago, verify on the vendor's website what the latest version is. 

If the current installation is not at the latest release, this is a finding."
  desc 'fix', "The software update process must be performed by the vendor's support organization.

Contact the vendor's support organization to determine if an update is available.

Note: it is possible no update is currently available for the specific product model being evaluated. This is not an error.

If an update is available, the support organization will use this process to install the software.

Acquire the system update image on DVD media from the vendor's support organization.

Power on the Service Processor, and apply its software update first.

Perform an Attach operation between the Service Processor and the disk array. Then apply the software update to the 3PAR system.

Perform a Detach operation between the Service Processor and the disk array, and power off the Service Processor."
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.2.x'
  tag check_id: 'C-41022r647843_chk'
  tag severity: 'medium'
  tag gid: 'V-237812'
  tag rid: 'SV-237812r647845_rule'
  tag stig_id: 'HP3P-32-001000'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-40981r647844_fix'
  tag 'documentable'
  tag legacy: ['SV-85079', 'V-70457']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
