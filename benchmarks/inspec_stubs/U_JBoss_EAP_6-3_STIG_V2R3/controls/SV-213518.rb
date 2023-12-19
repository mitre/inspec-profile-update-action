control 'SV-213518' do
  title 'JBoss process owner interactive access must be restricted.'
  desc 'JBoss does not require admin rights to operate and should be run as a regular user.  In addition, if the user account was to be compromised and the account was allowed interactive logon rights, this would increase the risk and attack surface against the JBoss system.  The right to interactively log on to the system using the JBoss account should be limited according to the OS capabilities.'
  desc 'check', 'Identify the user account used to run the JBoss server.  Use relevant OS commands to determine logon rights to the system. This account should not have full shell/interactive access to the system.

If the user account used to operate JBoss can log on interactively, this is a finding.'
  desc 'fix', 'Use the relevant OS commands to restrict JBoss user account from interactively logging on to the console of the JBoss system.

For Windows systems, use GPO.

For UNIX like systems using ssh DenyUsers <account id> or follow established procedure for restricting access.'
  impact 0.7
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14741r296220_chk'
  tag severity: 'high'
  tag gid: 'V-213518'
  tag rid: 'SV-213518r615939_rule'
  tag stig_id: 'JBOS-AS-000220'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-14739r296221_fix'
  tag 'documentable'
  tag legacy: ['SV-76751', 'V-62261']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
