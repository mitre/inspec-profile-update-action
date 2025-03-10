control 'SV-220050' do
  title 'The Sendmail server must have the debug feature disabled.'
  desc 'Debug mode is a feature present in older versions of Sendmail which, if not disabled, may allow an attacker to gain access to a system through the Sendmail service.'
  desc 'check', 'Check for an enabled debug command provided by the SMTP service.

Procedure:
# telnet localhost 25
debug

If the command does not return a 500 error code of command unrecognized, this is a finding.

If telnet is unavailable for testing, check the version of sendmail.  Run the following as a non-privileged user.

$ echo \\$Z | /usr/sbin/sendmail -bt -d0

If the version reported is less than 8.6, this is a finding.'
  desc 'fix', 'Obtain and install a more recent version of Sendmail, which does not implement the DEBUG feature.'
  impact 0.7
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21759r485144_chk'
  tag severity: 'high'
  tag gid: 'V-220050'
  tag rid: 'SV-220050r603265_rule'
  tag stig_id: 'GEN004620'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21758r485145_fix'
  tag 'documentable'
  tag legacy: ['SV-42311', 'V-4690']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
