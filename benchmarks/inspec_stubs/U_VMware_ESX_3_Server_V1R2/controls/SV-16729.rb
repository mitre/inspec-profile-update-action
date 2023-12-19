control 'SV-16729' do
  title 'iSCSI storage equipment is not configured with the latest patches and updates.'
  desc 'The ESX Server does not open any ports to listen for network connections. This measure reduces the chances that an intruder can attack the ESX Server through spare ports and possibly compromise the server. However, iSCSI device vulnerabilities may exist even though the ESX Server is configured properly. If security vulnerabilities exist in the iSCSI device software, data located on the iSCSI device may be at risk. To mitigate this risk, system administrators will install all security patches provided by the storage equipment manufacturer and limit the devices connected to the iSCSI network.'
  desc 'check', 'Validating the iSCSI device software will require the assistance of the system administrator. The system administrator will have to give you the version number of the software and validate that the software is at the latest version.  If the software is not at the latest version, this is a finding.'
  desc 'fix', 'Install the latest patches and updates to the iSCSI device.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-15977r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15790'
  tag rid: 'SV-16729r1_rule'
  tag stig_id: 'ESX0080'
  tag gtitle: 'iSCSI storage equipment not current with patches.'
  tag fix_id: 'F-15732r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
