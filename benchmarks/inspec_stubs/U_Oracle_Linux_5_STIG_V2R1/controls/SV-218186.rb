control 'SV-218186' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19661r553895_chk'
  tag severity: 'low'
  tag gid: 'V-218186'
  tag rid: 'SV-218186r603259_rule'
  tag stig_id: 'GEN000000-LNX00800'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19659r553896_fix'
  tag 'documentable'
  tag legacy: ['V-22584', 'SV-63085']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
