control 'SV-215410' do
  title 'AIX must be configured to only boot from the system boot device.'
  desc 'The ability to boot from removable media is the same as being able to boot into single user or maintenance mode without a password. This ability could allow a malicious user to boot the system and perform changes possibly compromising or damaging the system. It could also allow the system to be used for malicious purposes by a malicious anonymous user.'
  desc 'check', 'Determine if the system is configured to boot from devices other than the system startup media by running command: 
# bootlist -m normal -o 

The returned values should be "hdisk{x}". 

If the system is setup to boot from a non-hard disk device, this is a finding. 

Additionally, ask the SA if the machine is setup for "multi-boot" in the SMS application. If multi-boot is enabled, the firmware will stop at boot time and request which image to boot from the user. 

If "multi-boot" is enabled, this is a finding.'
  desc 'fix', 'Configure the system to only boot from system startup media:
# bootlist -m normal hdisk<x> 

Set "multi-boot" to "off" in the SMS application.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16608r294681_chk'
  tag severity: 'medium'
  tag gid: 'V-215410'
  tag rid: 'SV-215410r508663_rule'
  tag stig_id: 'AIX7-00-003112'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16606r294682_fix'
  tag 'documentable'
  tag legacy: ['SV-101745', 'V-91647']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
