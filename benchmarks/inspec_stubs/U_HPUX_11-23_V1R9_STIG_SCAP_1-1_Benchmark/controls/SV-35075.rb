control 'SV-35075' do
  title 'The SSH daemon must not permit Kerberos authentication unless needed.'
  desc "Kerberos authentication for SSH is often implemented using GSSAPI.  If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's Kerberos implementation.  Vulnerabilities in the system's Kerberos implementation may then be subject to exploitation.  To reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be disabled for systems not using this capability."
  desc 'fix', 'Edit the SSH daemon configuration and set (add if necessary) a KerberosAuthentication directive set to no.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'low'
  tag gid: 'V-22475'
  tag rid: 'SV-35075r1_rule'
  tag stig_id: 'GEN005526'
  tag gtitle: 'GEN005526'
  tag fix_id: 'F-30245r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
