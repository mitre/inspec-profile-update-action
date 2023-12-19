control 'SV-26978' do
  title 'The system must use a Linux Security Module configured to limit the privileges of system services.'
  desc 'Linux Security Modules such as SELinux and AppArmor can be used to provide protection from software exploits by explicitly defining the privileges permitted to each software package.'
  desc 'check', 'Check if SELinux is enabled with at least a "targeted" policy.

# grep ^SELINUX /etc/sysconfig/selinux

If the SELINUX option is not set to "enforcing", this is a finding.
If the SELINUXTYPE option is not set to "targeted" or "strict", this is a finding.

If the use of the system is incompatible with the confines of SELinux this rule may be waived.'
  desc 'fix', 'Enable one of the SELinux policies.
Edit /etc/sysconfig/selinux and set the value of the SELINUX option to "enforcing" and SELINUXTYPE to "targeted" or "strict".
Restart the system.'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36036r1_chk'
  tag severity: 'low'
  tag gid: 'V-22584'
  tag rid: 'SV-26978r1_rule'
  tag stig_id: 'GEN000000-LNX00800'
  tag gtitle: 'GEN000000-LNX00800'
  tag fix_id: 'F-31279r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
