control 'SV-218548' do
  title 'The sendmail server must have the debug feature disabled.'
  desc 'Debug mode is a feature present in older versions of sendmail which, if not disabled, may allow an attacker to gain access to a system through the sendmail service.'
  desc 'check', 'Check for an enabled "debug" command provided by the SMTP service.

Procedure:
# telnet localhost 25
debug

If the command does not return a 500 error code of "command unrecognized" or a 550 error code of "access denied", this is a finding.

The operating system distribution ships with sendmail Version 8.13.8 which is not vulnerable. This should never be a finding.'
  desc 'fix', 'Obtain and install a newer version of the SMTP service software (sendmail or Postfix) from the operating system vendor.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20023r555842_chk'
  tag severity: 'high'
  tag gid: 'V-218548'
  tag rid: 'SV-218548r603259_rule'
  tag stig_id: 'GEN004620'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20021r555843_fix'
  tag 'documentable'
  tag legacy: ['V-4690', 'SV-62813']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
