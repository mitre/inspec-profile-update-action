control 'SV-218611' do
  title 'The SSH daemon must not permit Kerberos authentication unless needed.'
  desc "Kerberos authentication for SSH is often implemented using GSSAPI.  If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's Kerberos implementation.  Vulnerabilities in the system's Kerberos implementation may then be subject to exploitation.  To reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be disabled for systems not using this capability."
  desc 'check', %q(Ask the SA if Kerberos authentication is used by the system. If it is, this is not applicable.

Check the SSH daemon configuration for the KerberosAuthentication setting.

# grep -i KerberosAuthentication /etc/ssh/sshd_config | grep -v '^#'
 
If no lines are returned, or the setting is set to "yes", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and set (add if necessary) the "KerberosAuthentication" directive set to "no".

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20086r562846_chk'
  tag severity: 'low'
  tag gid: 'V-218611'
  tag rid: 'SV-218611r603259_rule'
  tag stig_id: 'GEN005526'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20084r562847_fix'
  tag 'documentable'
  tag legacy: ['V-22475', 'SV-64033']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
