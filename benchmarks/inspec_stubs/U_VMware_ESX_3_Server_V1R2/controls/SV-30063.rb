control 'SV-30063' do
  title 'The telnet daemon must not be running.'
  desc 'The telnet daemon provides a typically unencrypted remote access service which does not provide for the confidentiality and integrity of user passwords or the remote session.  If a privileged user were to log on using this service, the privileged user password could be compromised.'
  desc 'check', "Consult vendor documentation to determine the method for determining if the telnet daemon is running.  If the system uses inetd, use the following procedure.
# grep -v '^#' /etc/inetd.conf | grep telnet
If an entry is returned, the telnet daemon is running.

If the telnet daemon is running, this is a finding."
  desc 'fix', 'Consult vendor documentation to determine the procedure to disable the telnet daemon.  If the system uses inetd, use the following procedure.
Edit the /etc/inetd.conf file and comment out the telnetd line.
Restart or reload the inetd process.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-30815r1_chk'
  tag severity: 'high'
  tag gid: 'V-24386'
  tag rid: 'SV-30063r1_rule'
  tag stig_id: 'GEN003850'
  tag gtitle: 'GEN003850'
  tag fix_id: 'F-27396r1_fix'
  tag 'documentable'
  tag mitigations: 'GEN003850'
  tag mitigation_control: 'If an enabled telnet daemon is configured to only allow encrypted sessions, such as with Kerberos or the use of encrypted network tunnels, the risk of exposing sensitive information is mitigated, and this is not a finding.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
