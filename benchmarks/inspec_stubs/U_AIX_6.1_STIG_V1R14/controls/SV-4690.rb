control 'SV-4690' do
  title 'The Sendmail server must have the debug feature disabled.'
  desc 'Debug mode is a feature present in older versions of Sendmail which, if not disabled, may allow an attacker to gain access to a system through the Sendmail service.'
  desc 'check', 'Check for an enabled debug command provided by the SMTP service.

Procedure:
# telnet localhost 25
debug

If the command does not return a 500 error code of command unrecognized, this is a finding.

If telnet is unavailable for testing, check the version of sendmail installed on the system.

# echo \\$Z | /usr/sbin/sendmail -bt -d0

If the sendmail reported version is less than 8.6, this is a finding.'
  desc 'fix', 'Obtain and install a more recent version of Sendmail, which does not implement the DEBUG feature.'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-652r3_chk'
  tag severity: 'high'
  tag gid: 'V-4690'
  tag rid: 'SV-4690r2_rule'
  tag stig_id: 'GEN004620'
  tag gtitle: 'GEN004620'
  tag fix_id: 'F-4618r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
