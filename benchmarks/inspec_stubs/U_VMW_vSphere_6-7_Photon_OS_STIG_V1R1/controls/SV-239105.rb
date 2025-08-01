control 'SV-239105' do
  title 'The Photon operating system must disable the loading of unnecessary kernel modules.'
  desc 'To support the requirements and principles of least functionality, the operating system must provide only essential capabilities and limit the use of modules, protocols, and/or services to only those required for the proper functioning of the product.

'
  desc 'check', 'At the command line, execute the following command:

# modprobe --showconfig | grep "^install" | grep "/bin"

Expected result:

install sctp /bin/false
install dccp /bin/false
install dccp_ipv4 /bin/false
install dccp_ipv6 /bin/false
install ipx /bin/false
install appletalk /bin/false
install decnet /bin/false
install rds /bin/false
install tipc /bin/false
install bluetooth /bin/false
install usb-storage /bin/false
install ieee1394 /bin/false
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/modprobe.d/modprobe.conf with a text editor and set the contents as follows:

install sctp /bin/false
install dccp /bin/false
install dccp_ipv4 /bin/false
install dccp_ipv6 /bin/false
install ipx /bin/false
install appletalk /bin/false
install decnet /bin/false
install rds /bin/false
install tipc /bin/false
install bluetooth /bin/false
install usb-storage /bin/false
install ieee1394 /bin/false
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42316r675121_chk'
  tag severity: 'medium'
  tag gid: 'V-239105'
  tag rid: 'SV-239105r675123_rule'
  tag stig_id: 'PHTN-67-000033'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42275r675122_fix'
  tag satisfies: ['SRG-OS-000096-GPOS-00050', 'SRG-OS-000114-GPOS-00059']
  tag 'documentable'
  tag cci: ['CCI-000382', 'CCI-000778']
  tag nist: ['CM-7 b', 'IA-3']
end
