control 'SV-37444' do
  title 'The telnet daemon must not be running.'
  desc 'The telnet daemon provides a typically unencrypted remote access service which does not provide for the confidentiality and integrity of user passwords or the remote session.  If a privileged user were to log on using this service, the privileged user password could be compromised.'
  desc 'fix', 'Identify the telnet service running and disable it.

Procedure:

Disable the telnet server.
# chkconfig telnet off

Verify the telnet daemon is no longer running.
# ps -ef |grep telnet'
  impact 0.7
  ref 'DPMS Target Red Hat 5'
  tag severity: 'high'
  tag gid: 'V-24386'
  tag rid: 'SV-37444r1_rule'
  tag stig_id: 'GEN003850'
  tag gtitle: 'GEN003850'
  tag fix_id: 'F-31362r2_fix'
  tag 'documentable'
  tag mitigations: 'GEN003850'
  tag mitigation_control: 'If an enabled telnet daemon is configured to only allow encrypted sessions, such as with Kerberos or the use of encrypted network tunnels, the risk of exposing sensitive information is mitigated, and this is not a finding.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
