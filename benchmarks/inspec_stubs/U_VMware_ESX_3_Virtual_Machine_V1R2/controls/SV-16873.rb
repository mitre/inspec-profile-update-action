control 'SV-16873' do
  title 'Anti-virus software and signatures are out of date for “off” and “suspended” virtual machines'
  desc 'Creating new virtual machines is as easy as copying a file. Copying files is a quick and efficient way to rollout new virtual machines. Virtual machines can grow at an explosive rate and really tax the security systems of an organization. Many administrative tasks may be automated, but some upgrades and patches require manual tools. For instance, virtual machines may need to be patched, scanned, and purged in response to a virus or worm attack on the network. Therefore, to protect against potential virus and spyware infections, all off and suspended virtual machines will have the latest up-to-date anti-virus software and signatures.'
  desc 'check', 'Work with the OS reviewer to determine if the requirement is being met.
1. Login to VirtualCenter with the VI Client and select a “suspended” or “off” virtual machine. 
2. Turn on the virtual machine and have the IAO/SA login.
3. Obtain the running virus engine and signatures from guest OS and compare this with the latest virus engine and signatures released from the JTG-GNO.  URL for JTG-GNO is https://www.jtfgno.mil/antivirus/av_info.htm.  If the signature or engine is older than the latest release, this is a finding.'
  desc 'fix', 'Apply the latest virus updates for all “off” and “suspended” virtual machines.'
  impact 0.5
  ref 'DPMS Target VMware Virtual Machine 3.x/4.x'
  tag check_id: 'C-16279r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15931'
  tag rid: 'SV-16873r1_rule'
  tag stig_id: 'ESX1200'
  tag gtitle: 'Anti-virus software and signatures out-of-date'
  tag fix_id: 'F-15877r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Guest Administrator]']
end
