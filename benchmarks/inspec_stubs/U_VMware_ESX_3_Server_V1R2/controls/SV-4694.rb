control 'SV-4694' do
  title 'The Sendmail service must not have the wizard backdoor active.'
  desc 'Very old installations of the Sendmail mailing system contained a feature whereby a remote user connecting to the SMTP port can enter the WIZ command and be given an interactive shell with root privileges.'
  desc 'check', 'Locate the sendmail.cf configuration file and check for wiz configuration.

Procedure:
# find / -name sendmail.cf -print
# grep -v "^#" <sendmail.cf location> |grep -i wiz

If an entry is found for wiz, this is a finding.'
  desc 'fix', 'If the WIZ command is enabled on Sendmail, it should be disabled by adding this line to the sendmail.cf configuration file (it must be typed in uppercase).

OW*

For the change to take effect, kill the Sendmail process, refreeze the sendmail.cf file, and restart the Sendmail process.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-706r2_chk'
  tag severity: 'low'
  tag gid: 'V-4694'
  tag rid: 'SV-4694r2_rule'
  tag stig_id: 'GEN004700'
  tag gtitle: 'GEN004700'
  tag fix_id: 'F-4622r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
