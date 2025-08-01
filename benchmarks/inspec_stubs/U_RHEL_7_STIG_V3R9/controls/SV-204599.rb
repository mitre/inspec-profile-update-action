control 'SV-204599' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit Kerberos authentication unless needed.'
  desc "Kerberos authentication for SSH is often implemented using Generic Security Service Application Program Interface (GSSAPI). If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's Kerberos implementation. Vulnerabilities in the system's Kerberos implementation may then be subject to exploitation. To reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be disabled for systems not using this capability."
  desc 'check', 'Verify the SSH daemon does not permit Kerberos to authenticate passwords unless approved.

Check that the SSH daemon does not permit Kerberos to authenticate passwords with the following command:

# grep -i kerberosauth /etc/ssh/sshd_config
KerberosAuthentication no

If the "KerberosAuthentication" keyword is missing, or is set to "yes" and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding.'
  desc 'fix', 'Uncomment the "KerberosAuthentication" keyword in "/etc/ssh/sshd_config" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and set the value to "no":

KerberosAuthentication no

The SSH service must be restarted for changes to take effect.

If Kerberos authentication is required, it must be documented, to include the location of the configuration file, with the ISSO.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4723r88989_chk'
  tag severity: 'medium'
  tag gid: 'V-204599'
  tag rid: 'SV-204599r853994_rule'
  tag stig_id: 'RHEL-07-040440'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-4723r88990_fix'
  tag 'documentable'
  tag legacy: ['V-72261', 'SV-86885']
  tag cci: ['CCI-000318', 'CCI-000368', 'CCI-001812', 'CCI-001813', 'CCI-001814']
  tag nist: ['CM-3 f', 'CM-6 c', 'CM-11 (2)', 'CM-5 (1) (a)', 'CM-5 (1)']
end
