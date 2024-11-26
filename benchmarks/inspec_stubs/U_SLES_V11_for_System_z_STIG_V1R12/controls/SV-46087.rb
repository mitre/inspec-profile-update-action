control 'SV-46087' do
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
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43344r1_chk'
  tag severity: 'low'
  tag gid: 'V-22475'
  tag rid: 'SV-46087r2_rule'
  tag stig_id: 'GEN005526'
  tag gtitle: 'GEN005526'
  tag fix_id: 'F-39431r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
