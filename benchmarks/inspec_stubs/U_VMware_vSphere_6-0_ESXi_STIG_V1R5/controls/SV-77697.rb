control 'SV-77697' do
  title 'The SSH daemon must not permit Kerberos authentication.'
  desc "Kerberos authentication for SSH is often implemented using GSSAPI.  If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's Kerberos implementation.  Vulnerabilities in the system's Kerberos implementation may then be subject to exploitation.  To reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be disabled for systems."
  desc 'check', 'To verify the KerberosAuthentication setting, run the following command: 

# grep -i "^KerberosAuthentication" /etc/ssh/sshd_config

If there is no output or the output is not exactly "KerberosAuthentication no", this is a finding.'
  desc 'fix', 'To set the KerberosAuthentication setting, add or correct the following line in "/etc/ssh/sshd_config":

KerberosAuthentication no'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63941r1_chk'
  tag severity: 'low'
  tag gid: 'V-63207'
  tag rid: 'SV-77697r1_rule'
  tag stig_id: 'ESXI-06-000019'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69125r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
