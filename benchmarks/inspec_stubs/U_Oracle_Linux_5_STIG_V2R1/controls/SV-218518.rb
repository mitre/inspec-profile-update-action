control 'SV-218518' do
  title 'The telnet daemon must not be running.'
  desc 'The telnet daemon provides a typically unencrypted remote access service which does not provide for the confidentiality and integrity of user passwords or the remote session.  If a privileged user were to log on using this service, the privileged user password could be compromised.'
  desc 'check', 'The telnet service included in the operating system is a part of krb5-workstation. There are two versions of telnetd server provided. The xinetd.d file ekrb5-telnet allows only connections authenticated through Kerberos. The xinetd.d krb5-telnet allows normal telnet connections as well as kerberized connections. Both are set to "disable = yes" by default. Ensure that neither is running.

Procedure:
Check if telnetd is running:

# ps -ef |grep telnetd

If the telnet daemon is running, this is a finding.

Check if telnetd is enabled on startup:

# chkconfig --list|grep telnet

If an entry with "on" is found, this is a finding.'
  desc 'fix', 'Identify the telnet service running and disable it.

Procedure:

Disable the telnet server.
# chkconfig telnet off

Verify the telnet daemon is no longer running.
# ps -ef |grep telnet'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19993r562678_chk'
  tag severity: 'high'
  tag gid: 'V-218518'
  tag rid: 'SV-218518r603259_rule'
  tag stig_id: 'GEN003850'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-19991r562679_fix'
  tag 'documentable'
  tag legacy: ['V-24386', 'SV-64021']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
