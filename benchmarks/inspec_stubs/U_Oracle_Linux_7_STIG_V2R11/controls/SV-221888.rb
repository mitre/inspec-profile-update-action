control 'SV-221888' do
  title 'The Oracle Linux operating system must not have a graphical display manager installed unless approved.'
  desc 'Internet services not required for system or application processes must not be active to decrease the attack surface of the system. Graphical display managers have a long history of security vulnerabilities and must not be used unless approved and documented.'
  desc 'check', 'Verify the system is configured to boot to the command line:

$ systemctl get-default
multi-user.target

If the system default target is not set to "multi-user.target" and the Information System Security Officer (ISSO) lacks a documented requirement for a graphical user interface, this is a finding.

Verify that a graphical user interface is not installed:

$ rpm -qa | grep xorg | grep server

Ask the System Administrator if use of a graphical user interface is an operational requirement.

If the use of a graphical user interface on the system is not documented with the ISSO, this is a finding.'
  desc 'fix', 'Document the requirement for a graphical user interface with the ISSO or reinstall the operating system without the graphical user interface. If reinstallation is not feasible, then continue with the following procedure:

Open an SSH session and enter the following commands:

$ sudo systemctl set-default multi-user.target

$ sudo yum remove xorg-x11-server-Xorg xorg-x11-server-common xorg-x11-server-utils

A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36329r646959_chk'
  tag severity: 'medium'
  tag gid: 'V-221888'
  tag rid: 'SV-221888r646961_rule'
  tag stig_id: 'OL07-00-040730'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-36293r646960_fix'
  tag 'documentable'
  tag legacy: ['SV-108619', 'V-99515']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
