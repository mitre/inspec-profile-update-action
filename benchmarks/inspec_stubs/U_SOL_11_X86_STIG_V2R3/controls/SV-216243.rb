control 'SV-216243' do
  title 'The operating system must monitor for unauthorized connections of mobile devices to organizational information systems.'
  desc 'Mobile devices include portable storage media (e.g., USB memory sticks, external hard disk drives) and portable computing and communications devices with information storage capability (e.g., notebook/laptop computers, personal digital assistants, cellular telephones, digital cameras, audio recording devices). 

Organization-controlled mobile devices include those devices for which the organization has the authority to specify and the ability to enforce specific security requirements.

Usage restrictions and implementation guidance related to mobile devices include configuration management, device identification and authentication, implementation of mandatory protective software (e.g., malicious code detection, firewall), scanning devices for malicious code, updating virus protection software, scanning for critical software updates and patches, conducting primary operating system (and possibly other resident software) integrity checks, and disabling unnecessary hardware (e.g., wireless, infrared).

In order to detect unauthorized mobile device connections, organizations must first identify and document what mobile devices are authorized.'
  desc 'check', 'This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global" this check applies.

Determine if USB mass storage devices are locked out by the kernel.

# grep -h "exclude: scsa2usb" /etc/system /etc/system.d/*

If the output of this command is not:

exclude: scsa2usb

this is a finding.'
  desc 'fix', 'The root role is required.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global" this check applies.

Modify the /etc/system file.

Determine the OS version you are currently securing.
# uname –v
For Solaris 11GA and 11.1
# pfedit /etc/system

Add a line containing:

exclude: scsa2usb

Note that the global zone will need to be rebooted for this change to take effect.   

For Solaris 11.2 or newer

Modify an /etc/system.d file.
# pfedit /etc/system.d/USB:MassStorage

Add a line containing:
exclude: scsa2usb

Note that the global zone will need to be rebooted for this change to take effect.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17481r373105_chk'
  tag severity: 'medium'
  tag gid: 'V-216243'
  tag rid: 'SV-216243r603268_rule'
  tag stig_id: 'SOL-11.1-120410'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17479r373106_fix'
  tag 'documentable'
  tag legacy: ['V-49635', 'SV-62559']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
