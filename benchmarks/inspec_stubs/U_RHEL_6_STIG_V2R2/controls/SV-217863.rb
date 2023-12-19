control 'SV-217863' do
  title 'The system must use a Linux Security Module configured to limit the privileges of system services.'
  desc 'Setting the SELinux policy to "targeted" or a more specialized policy ensures the system will confine processes that are likely to be targeted for exploitation, such as network or system services.'
  desc 'check', 'Check the file "/etc/selinux/config" and ensure the following line appears:

SELINUXTYPE=targeted

If it does not, this is a finding.'
  desc 'fix', 'The SELinux "targeted" policy is appropriate for general-purpose desktops and servers, as well as systems in many other roles. To configure the system to use this policy, add or correct the following line in "/etc/selinux/config":

SELINUXTYPE=targeted

Other policies, such as "mls", provide additional security labeling and greater confinement but are not compatible with many general-purpose use cases.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19344r376604_chk'
  tag severity: 'low'
  tag gid: 'V-217863'
  tag rid: 'SV-217863r603264_rule'
  tag stig_id: 'RHEL-06-000023'
  tag gtitle: 'SRG-OS-000324'
  tag fix_id: 'F-19342r376605_fix'
  tag 'documentable'
  tag legacy: ['V-51369', 'SV-65579']
  tag cci: ['CCI-002235', 'CCI-002165']
  tag nist: ['AC-6 (10)', 'AC-3 (4)']
end
