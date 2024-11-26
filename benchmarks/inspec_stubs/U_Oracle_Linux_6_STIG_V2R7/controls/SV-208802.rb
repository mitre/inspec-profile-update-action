control 'SV-208802' do
  title 'The system must use a Linux Security Module configured to limit the privileges of system services.'
  desc 'Setting the SELinux policy to "targeted" or a more specialized policy ensures the system will confine processes that are likely to be targeted for exploitation, such as network or system services.'
  desc 'check', 'Check the file "/etc/selinux/config" and ensure the following line appears:

SELINUXTYPE=targeted

If it does not, this is a finding.'
  desc 'fix', 'The SELinux "targeted" policy is appropriate for general-purpose desktops and servers, as well as systems in many other roles. To configure the system to use this policy, add or correct the following line in "/etc/selinux/config":

SELINUXTYPE=targeted

Other policies, such as "mls", provide additional security labeling and greater confinement but are not compatible with many general-purpose use cases.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9055r357386_chk'
  tag severity: 'low'
  tag gid: 'V-208802'
  tag rid: 'SV-208802r793587_rule'
  tag stig_id: 'OL6-00-000023'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9055r357387_fix'
  tag 'documentable'
  tag legacy: ['SV-73799', 'V-59369']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
