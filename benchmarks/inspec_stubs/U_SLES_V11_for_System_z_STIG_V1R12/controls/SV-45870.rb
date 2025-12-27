control 'SV-45870' do
  title 'The sendmail server must have the debug feature disabled.'
  desc 'Debug mode is a feature present in older versions of sendmail which, if not disabled, may allow an attacker to gain access to a system through the sendmail service.'
  desc 'check', 'Check for an enabled "debug" command provided by the SMTP service.

Procedure:
# telnet localhost 25
debug

If the command does not return a 500 error code of "command unrecognized", this is a finding.

The SLES mainframe distribution ships with sendmail Version 8.14.3.-50.20.1 which is not vulnerable. This should never be a finding.'
  desc 'fix', 'Obtain and install a newer version of the SMTP service software (sendmail or Postfix) fromNovell.'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43187r1_chk'
  tag severity: 'high'
  tag gid: 'V-4690'
  tag rid: 'SV-45870r1_rule'
  tag stig_id: 'GEN004620'
  tag gtitle: 'GEN004620'
  tag fix_id: 'F-39248r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
