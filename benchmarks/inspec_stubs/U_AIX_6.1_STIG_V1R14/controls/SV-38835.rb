control 'SV-38835' do
  title 'The system must be configured to only boot from the system boot device.'
  desc 'The ability to boot from removable media is the same as being able to boot into single user, or maintenance, mode without a password.  This ability could allow a malicious user to boot the system and perform changes that could compromise or damage the system.  It could also allow the system to be used for malicious purposes by a malicious anonymous user.'
  desc 'check', 'Determine if the system is configured to boot from devices other than the system startup media. 
# bootlist -m normal -o
The returned values should be hdisk{x}.   If the system is setup to boot from a non-hard disk device,  this is a finding. 
 
Additionally, ask the SA if the machine is setup for multi-boot in the SMS application.   If multi-boot is enabled,  the firmware will stop at boot time and request which image to boot from the user.   If multi-boot is enabled,  this is a finding.'
  desc 'fix', 'Configure the system to only boot from system startup media.

# bootlist -m normal hdisk< x >

Set multi-boot to off in the SMS application.'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37096r1_chk'
  tag severity: 'high'
  tag gid: 'V-1013'
  tag rid: 'SV-38835r1_rule'
  tag stig_id: 'GEN008600'
  tag gtitle: 'GEN008600'
  tag fix_id: 'F-32367r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
