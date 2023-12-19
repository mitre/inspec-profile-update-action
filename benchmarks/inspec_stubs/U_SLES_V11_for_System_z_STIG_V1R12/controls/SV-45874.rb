control 'SV-45874' do
  title 'The sendmail service must not have the wizard backdoor active.'
  desc 'Very old installations of the Sendmail mailing system contained a feature whereby a remote user connecting to the SMTP port can enter the WIZ command and be given an interactive shell with root privileges.'
  desc 'check', 'Log into the sendmail server with telnet and test the "wiz" commmand"

Procedure:
# telnet localhost 25

Trying 127.0.0.1...
Connected to locahost.localdomain (127.0.0.1).
Escape character ...

Once the telnet greeting is complete type:
wiz

If you do not get a "Command unrecognized: " message, this is a finding.'
  desc 'fix', 'If the WIZ command exists on sendmail then the version of sendmail is archaic and should be replaced with the latest version fromNovell.
If the WIZ command is enabled on sendmail, it should be disabled by adding this line to the sendmail.cf configuration file (note that it must be typed in uppercase):

OW*

For the change to take effect, kill the sendmail process, refreeze the sendmail.cf file, and restart the sendmail process.'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43191r1_chk'
  tag severity: 'low'
  tag gid: 'V-4694'
  tag rid: 'SV-45874r1_rule'
  tag stig_id: 'GEN004700'
  tag gtitle: 'GEN004700'
  tag fix_id: 'F-39252r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
