control 'SV-45809' do
  title 'The telnet daemon must not be running.'
  desc 'The telnet daemon provides a typically unencrypted remote access service which does not provide for the confidentiality and integrity of user passwords or the remote session.  If a privileged user were to log on using this service, the privileged user password could be compromised.'
  desc 'check', '# chkconfig --list | grep telnet
If an entry is returned and any run level is “on” telnet is running.

If the telnet daemon is running, this is a finding.'
  desc 'fix', 'Identify the telnet service running and disable it.

Procedure
# insserv –r telnetd

If telnet is running as an xinetd service,  edit the /etc/xinetd.d file and set “disable = yes” and then restart the xinetd service:
# rcxinetd restart


disable the telnet server:
chkconfig telnet off

verify the telnet daemon is no longer running:

# ps -ef |grep telnet'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43130r1_chk'
  tag severity: 'high'
  tag gid: 'V-24386'
  tag rid: 'SV-45809r1_rule'
  tag stig_id: 'GEN003850'
  tag gtitle: 'GEN003850'
  tag fix_id: 'F-39199r1_fix'
  tag 'documentable'
  tag mitigations: 'GEN003850'
  tag mitigation_control: 'If an enabled telnet daemon is configured to only allow encrypted sessions, such as with Kerberos or the use of encrypted network tunnels, the risk of exposing sensitive information is mitigated, and this is not a finding.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
