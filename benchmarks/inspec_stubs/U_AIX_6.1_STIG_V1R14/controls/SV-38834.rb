control 'SV-38834' do
  title 'The system must have USB Mass Storage disabled unless needed.'
  desc 'USB is a common computer peripheral interface.  USB devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', 'If the system uses USB mass storage, this is not applicable.
# lslpp -l | grep -e devices.usbif.010100 -e devices.usbif.08025 -e devices.usbif.080400
If these filesets are installed on the system, USB mass storage is enabled and this is a finding.'
  desc 'fix', 'Disable USB mass storage on the system by using SMIT to remove the following filesets.
devices.usbif.010100
devices.usbif.08025002
devices.usbif.080400  

# smitty remove'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37091r1_chk'
  tag severity: 'low'
  tag gid: 'V-22579'
  tag rid: 'SV-38834r1_rule'
  tag stig_id: 'GEN008480'
  tag gtitle: 'GEN008480'
  tag fix_id: 'F-32362r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
