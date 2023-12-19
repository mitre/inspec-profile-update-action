control 'SV-208799' do
  title 'The system must use a Linux Security Module at boot time.'
  desc 'Disabling a major host protection feature, such as SELinux, at boot time prevents it from confining system services at boot time. Further, it increases the chances that it will remain off during system operation.'
  desc 'check', 'Inspect "/boot/grub/grub.conf" for any instances of "selinux=0" in the kernel boot arguments. Presence of "selinux=0" indicates that SELinux is disabled at boot time. If SELinux is disabled at boot time, this is a finding.'
  desc 'fix', 'SELinux can be disabled at boot time by an argument in "/boot/grub/grub.conf". Remove any instances of "selinux=0" from the kernel arguments in that file to prevent SELinux from being disabled at boot.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9052r357377_chk'
  tag severity: 'medium'
  tag gid: 'V-208799'
  tag rid: 'SV-208799r793584_rule'
  tag stig_id: 'OL6-00-000017'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9052r357378_fix'
  tag 'documentable'
  tag legacy: ['SV-73777', 'V-59347']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
