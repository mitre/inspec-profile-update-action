control 'SV-35134' do
  title 'The telnet daemon must not be running.'
  desc 'The telnet daemon provides a typically unencrypted remote access service which does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised.'
  desc 'check', %q(Consult vendor documentation to determine the method for determining if the telnet daemon is running. If the system uses inetd, use the following procedure:
# cat /etc/inetd.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[  \t]*//'  |grep -v "^#" | \
cut -f 6,7 -d " " | grep -c -i telnetd 

If the above command returns a number greater than 0, the telnet daemon is running.

If the telnet daemon is running, this is a finding.)
  desc 'fix', 'Consult vendor documentation to determine the procedure to disable the telnet daemon. If the system uses inetd, edit /etc/inetd.conf and comment out the telnetd line. Restart the inetd service via the following command:
# inetd -c'
  impact 0.7
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-34992r1_chk'
  tag severity: 'high'
  tag gid: 'V-24386'
  tag rid: 'SV-35134r1_rule'
  tag stig_id: 'GEN003850'
  tag gtitle: 'GEN003850'
  tag fix_id: 'F-30286r1_fix'
  tag 'documentable'
  tag mitigations: 'GEN003850'
  tag mitigation_control: 'If an enabled telnet daemon is configured to only allow encrypted sessions, such as with Kerberos or the use of encrypted network tunnels, the risk of exposing sensitive information is mitigated, and this is not a finding.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
