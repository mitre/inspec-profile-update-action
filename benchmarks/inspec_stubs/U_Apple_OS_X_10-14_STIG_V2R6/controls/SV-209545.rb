control 'SV-209545' do
  title 'The macOS system must limit the number of concurrent SSH sessions to 10 for all accounts and/or account types.'
  desc 'Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'To verify that SSHD is limited to 10 sessions, use the following command:

/bin/cat /etc/ssh/sshd_config | grep MaxSessions

The command must return "MaxSessions 10". If it returns null, or a commented value, or the value is greater than "10", this is a finding.'
  desc 'fix', "To configure SSHD to limit the number of sessions, use the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\\#]*MaxSessions.*/MaxSessions 10/' /etc/ssh/sshd_config"
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9796r282117_chk'
  tag severity: 'medium'
  tag gid: 'V-209545'
  tag rid: 'SV-209545r610285_rule'
  tag stig_id: 'AOSX-14-000050'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag fix_id: 'F-9796r282118_fix'
  tag 'documentable'
  tag legacy: ['SV-104717', 'V-95407']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
