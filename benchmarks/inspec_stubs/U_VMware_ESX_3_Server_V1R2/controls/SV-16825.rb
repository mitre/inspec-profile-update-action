control 'SV-16825' do
  title 'ISO images are not restricted to authorized users.'
  desc 'Virtual machines are created from using operating system CD-ROMs or ISO images of the operating system. ISO operating system images reduce the time in deploying virtual machine servers since the media is readily available as a file on the hard drive. Also, ISO operating system images map easily to the virtual machine CD-ROM drive of the guest machine once the guest machine is running. Unauthorized access to the ISO operating system images could potentially allow these images to be corrupted or altered in some way.'
  desc 'check', 'On the ESX Server service console perform the following command to determine if the /ISO, /Utilities, or /vmimages file partitions are accessible to unauthorized users.

# ls -la /vmimages (Or the name of the partition) 

Permissions for .iso files should be 440 (r--r-----). If they are not 440 or more restrictive, this is a finding.'
  desc 'fix', 'Restrict iso images to only authorized users.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16243r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15884'
  tag rid: 'SV-16825r1_rule'
  tag stig_id: 'ESX0880'
  tag gtitle: 'ISO images are not restricted to authorized users'
  tag fix_id: 'F-15844r1_fix'
  tag 'documentable'
  tag responsibility: ['[Virtual Machine Administrator]', 'Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECAN-1, ECCD-1, ECCD-2'
end
