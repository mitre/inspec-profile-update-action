control 'SV-209622' do
  title 'macOS must be configured with a firmware password to prevent access to single user mode and booting from alternative media.'
  desc 'Single user mode and the boot picker, as well as numerous other tools are available on macOS through booting while holding the "Option" key down. Setting a firmware password restricts access to these tools.'
  desc 'check', 'To check that password hints are disabled, run the following command:

# sudo /usr/sbin/firmwarepasswd -check

If the return is not, "Password Enabled: Yes", this is a finding.'
  desc 'fix', 'To set a firmware passcode use the following command.

sudo /usr/sbin/firmwarepasswd -setpasswd

Note: If firmware password or passcode is forgotten, the only way to reset the forgotten password is through the use of a machine specific binary generated and provided by Apple. Schedule a support call, and provide proof of purchase before the firmware binary will be generated.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9873r466318_chk'
  tag severity: 'medium'
  tag gid: 'V-209622'
  tag rid: 'SV-209622r610285_rule'
  tag stig_id: 'AOSX-14-003013'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-9873r466319_fix'
  tag 'documentable'
  tag legacy: ['SV-105113', 'V-95975']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
