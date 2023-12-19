control 'SV-16874' do
  title 'OS patches and updates are out of date on “off” and “suspended” virtual machines.'
  desc 'Virtual machines create a condition where they may be on, off, or suspended.  The requirement that machines be on in a conventional approach to patch management, virus and vulnerability scanning, and machine configuration creates an issue in the virtual world. Virtual machines can appear and disappear from the network sporadically. Conventional networks can “anneal” new machines into a known good configuration state very quickly. However, converging virtual machines to a known good state is more challenging since the state may change quickly.  For instance, a vulnerable machine can appear briefly and either become infected or reappear in a vulnerable state at a later time. Therefore, vulnerable virtual machines may become infected with a virus and never be detected since the virtual machine may be suspended or off.  Suspended and off virtual machines should be patched regularly to ensure patches are up to date. Virtual machines that are on will be kept current with the OS per the appropriate OS STIG.'
  desc 'check', 'Work with the OS reviewer to determine if the requirement is being met.
1. Login to VirtualCenter with the VI Client and select a suspended or off virtual machine. 
2. Turn on the virtual machine and have the IAO/SA login.
3. Have the IAO/SA obtain the latest patch level for the OS and compare this to the latest release from the OS vendor.  If the patch level is older than the latest release, this is a finding.'
  desc 'fix', 'Apply the latest OS patches for all “suspended” and “off” virtual machines.'
  impact 0.5
  ref 'DPMS Target VMware Virtual Machine 3.x/4.x'
  tag check_id: 'C-16280r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15932'
  tag rid: 'SV-16874r1_rule'
  tag stig_id: 'ESX1210'
  tag gtitle: 'OS patches and updates out of date'
  tag fix_id: 'F-15878r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Guest Administrator]']
  tag ia_controls: 'ECSC-1'
end
