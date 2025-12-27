control 'SV-225211' do
  title 'The macOS system must be configured with a firmware password to prevent access to single user mode and booting from alternative media.'
  desc 'Single user mode and the boot picker, as well as numerous other tools are available on macOS through booting while holding the "Option" key down. Setting a firmware password restricts access to these tools.'
  desc 'check', 'To ensure that a firmware password is set, run the following command:

# sudo /usr/sbin/firmwarepasswd -check

If the return is not, "Password Enabled: Yes", this is a finding'
  desc 'fix', 'To set a firmware passcode use the following command.

sudo /usr/sbin/firmwarepasswd -setpasswd

Note: If firmware password or passcode is forgotten, the only way to reset the forgotten password is through the use of a machine specific binary generated and provided by Apple. Schedule a support call, and provide proof of purchase before the firmware binary will be generated.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26910r467801_chk'
  tag severity: 'medium'
  tag gid: 'V-225211'
  tag rid: 'SV-225211r610901_rule'
  tag stig_id: 'AOSX-15-003013'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26898r485774_fix'
  tag 'documentable'
  tag legacy: ['V-102841', 'SV-111803']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
