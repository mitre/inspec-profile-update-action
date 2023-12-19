control 'SV-248828' do
  title 'OL 8 must cover or disable the built-in or attached camera when not in use.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors. 
 
Failing to disconnect from collaborative computing devices (i.e., cameras) can result in subsequent compromises of organizational information. Providing easy methods to physically disconnect from such devices after a collaborative computing session helps to ensure participants actually carry out the disconnect activity without having to go through complex and tedious procedures.'
  desc 'check', 'If the device or operating system does not have a camera installed, this requirement is not applicable.

This requirement is not applicable to mobile devices (smartphones and tablets), where the use of the camera is a local AO decision.

This requirement is not applicable to dedicated VTC suites located in approved VTC locations that are centrally managed.

For an external camera, if there is not a method for the operator to manually disconnect the camera at the end of collaborative computing sessions, this is a finding.

For a built-in camera, the camera must be protected by a camera cover (e.g., laptop camera cover slide) when not in use.

If the built-in camera is not protected with a camera cover or is not physically disabled, this is a finding.

If the camera is not disconnected, covered, or physically disabled, determine if it is being disabled via software with the following commands:

Verify the operating system disables the ability to load the uvcvideo kernel module.

$ sudo grep -r uvcvideo /etc/modprobe.d/* | grep "/bin/true"

install uvcvideo /bin/true

If the command does not return any output, or the line is commented out, and the collaborative computing device has not been authorized for use, this is a finding.

Verify the camera is disabled via blacklist with the following command:

$ sudo grep -r uvcvideo /etc/modprobe.d/* | grep "blacklist"

blacklist uvcvideo

If the command does not return any output or the output is not "blacklist uvcvideo", and the collaborative computing device has not been authorized for use, this is a finding.'
  desc 'fix', 'Configure OL 8 to disable the built-in or attached camera when not in use.

Build or modify the "/etc/modprobe.d/blacklist.conf" file by using the following example:

install uvcvideo /bin/true
blacklist uvcvideo

Reboot the system for the settings to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52262r818689_chk'
  tag severity: 'medium'
  tag gid: 'V-248828'
  tag rid: 'SV-248828r818691_rule'
  tag stig_id: 'OL08-00-040020'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-52216r818690_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
