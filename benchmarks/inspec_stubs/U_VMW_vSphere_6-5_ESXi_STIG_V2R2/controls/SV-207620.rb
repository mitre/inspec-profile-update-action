control 'SV-207620' do
  title 'The ESXi host SSH daemon must not permit Kerberos authentication.'
  desc "Kerberos authentication for SSH is often implemented using GSSAPI.  If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's Kerberos implementation.  Vulnerabilities in the system's Kerberos implementation may then be subject to exploitation.  To reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be disabled for systems."
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^KerberosAuthentication" /etc/ssh/sshd_config

If there is no output or the output is not exactly "KerberosAuthentication no", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

KerberosAuthentication no'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7875r364259_chk'
  tag severity: 'low'
  tag gid: 'V-207620'
  tag rid: 'SV-207620r388482_rule'
  tag stig_id: 'ESXI-65-000019'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7875r364260_fix'
  tag 'documentable'
  tag legacy: ['V-93985', 'SV-104071']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
