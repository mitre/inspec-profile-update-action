control 'SV-6751' do
  title 'All the network level devices interconnected to the SAN are not located in a secure room with limited access.'
  desc 'If the network level devices are not located in a secure area they can be tampered with which could lead to a denial of service if the device is powered off or sensitive data can be compromised by a tap connected to the device.
The IAO/NSO will ensure that all the network level devices interconnected to the SAN are located in a secure room with limited access.'
  desc 'check', 'The reviewer will interview the IAO/NSO and view the network level devices to verify whether they are located in a secure room with limited access.'
  desc 'fix', 'Develop a plan to move the network level devices to a location/room where the can be physically secured in a manner appropriate to the classification level of the data the handle.  Obtain CM approval of the plan and then implement the plan moving the devices.'
  impact 0.5
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2485r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6631'
  tag rid: 'SV-6751r1_rule'
  tag stig_id: 'SAN04.008.00'
  tag gtitle: 'Physical Access to SAN Network Devices'
  tag fix_id: 'F-6219r1_fix'
  tag 'documentable'
  tag potential_impacts: 'Moving devices can disrupt the SAN environment while the move is taking place.'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
  tag ia_controls: 'PECF-1, PECF-2'
end
