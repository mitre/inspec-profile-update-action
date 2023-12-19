control 'SV-218552' do
  title 'The sendmail service must not have the wizard backdoor active.'
  desc 'Very old installations of the Sendmail mailing system contained a feature whereby a remote user connecting to the SMTP port can enter the WIZ command and be given an interactive shell with root privileges.'
  desc 'check', 'Log into the sendmail server with telnet and test the "wiz" command.

Procedure:
# telnet localhost 25

Trying 127.0.0.1...
Connected to locahost.localdomain (127.0.0.1).
Escape character ...

Once the telnet greeting is complete type:
wiz

If you do not get a "Command unrecognized: " message, this is a finding.'
  desc 'fix', 'If the WIZ command exists on sendmail then the version of sendmail is archaic and should be replaced with the latest version from the operating system vendor.  WIZ is not available on any sendmail distribution delivered by this operating system.

However, if the WIZ command is enabled on sendmail, it should be disabled by adding this line to the sendmail.cf configuration file (note that it must be typed in uppercase):

OW*

For the change to take effect, kill the sendmail process, refreeze the sendmail.cf file, and restart the sendmail process.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20027r555854_chk'
  tag severity: 'low'
  tag gid: 'V-218552'
  tag rid: 'SV-218552r603259_rule'
  tag stig_id: 'GEN004700'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20025r555855_fix'
  tag 'documentable'
  tag legacy: ['V-4694', 'SV-62867']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
