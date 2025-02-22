control 'SV-86199' do
  title 'The CA API Gateway must employ automated mechanisms to detect the addition of unauthorized components or devices.'
  desc 'This requirement addresses configuration management of the network device. The network device must automatically detect the installation of unauthorized software or hardware onto the device itself. Monitoring may be accomplished on an ongoing basis or by periodic monitoring. Automated mechanisms can be implemented within the network device and/or in another separate information system or device. If the addition of unauthorized components or devices is not automatically detected, then such components or devices could be used for malicious purposes, such as transferring sensitive data to removable media for compromise.'
  desc 'check', 'Verify "/etc/modprobe.d/ssg-harden.conf" contents are:

install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install net-pf-31 /bin/false
install bluetooth /bin/false
install usb-storage /bin/false
options ipv6 disable=1

If the "/etc/modprobe.d/ssg-harden.conf" contents do not contain the above, this is a finding.'
  desc 'fix', 'Set contents of "/etc/modprobe.d/ssg-harden.conf" file to:

install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install net-pf-31 /bin/false
install bluetooth /bin/false
install usb-storage /bin/false
options ipv6 disable=1'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71953r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71575'
  tag rid: 'SV-86199r1_rule'
  tag stig_id: 'CAGW-DM-000370'
  tag gtitle: 'SRG-APP-000516-NDM-000339'
  tag fix_id: 'F-77899r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000416']
  tag nist: ['CM-6 b', 'CM-8 (3) (a)']
end
