control 'SV-38833' do
  title 'The system must have USB disabled unless needed.'
  desc 'USB is a common computer peripheral interface. USB devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', 'AIX has server USB drivers installed, such as keyboard, mount, and mass media drivers.

Determine if the system has USB enabled.
# lsdev -C | grep usb
# lslpp -l  | grep usb

If usb filesets are installed on the system, USB is enabled and this is a finding.'
  desc 'fix', 'Disable USB devices on the system.  Use SMIT to remove the following filesets.

devices.usbif.*

# smitty remove'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37092r1_chk'
  tag severity: 'low'
  tag gid: 'V-22578'
  tag rid: 'SV-38833r1_rule'
  tag stig_id: 'GEN008460'
  tag gtitle: 'GEN008460'
  tag fix_id: 'F-32361r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
