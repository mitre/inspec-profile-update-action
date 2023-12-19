control 'SV-257232' do
  title 'The macOS system must be configured with a firmware password to prevent access to single user mode and booting from alternative media.'
  desc 'Single user mode and the boot picker, as well as numerous other tools, are available on macOS through booting while holding the "Option" key down. Setting a firmware password restricts access to these tools.'
  desc 'check', 'For Apple Silicon-based systems, this is not applicable.

Verify the macOS system is configured with a firmware password with the following command:

/usr/bin/sudo /usr/sbin/firmwarepasswd -check

Password Enabled:Yes

If "Password Enabled" is not set to "Yes", this is a finding.'
  desc 'fix', 'Configure the macOS system with a firmware password with the following command:

/usr/bin/sudo /usr/sbin/firmwarepasswd -setpasswd

Note: If firmware password or passcode is forgotten, the only way to reset the forgotten password is through a machine-specific binary generated and provided by Apple. Users must schedule a support call and provide proof of purchase before the firmware binary will be generated.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60917r905327_chk'
  tag severity: 'medium'
  tag gid: 'V-257232'
  tag rid: 'SV-257232r905329_rule'
  tag stig_id: 'APPL-13-003013'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60858r905328_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
