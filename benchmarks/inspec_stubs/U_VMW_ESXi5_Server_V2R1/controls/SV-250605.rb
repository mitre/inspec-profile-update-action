control 'SV-250605' do
  title 'The nosuid option must be enabled on all NFS client mounts.'
  desc 'Enabling the nosuid mount option prevents the system from granting owner or group owner privileges to programs with the suid or sgid bit set. If the system does not restrict this access, users with unprivileged access to the local system may be able to acquire privileged access by executing setuid or setgid files located on the mounted NFS file system.'
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required. 

As root, log in to the host.  Check the system for NFS mounts that do not use the nosuid option. Execute the following:
#  cat /etc/fstab | grep -i nfs | grep -v "nosuid"

If the mounted NFS file systems do not use the nosuid option, this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required. As root, log in to the host.  Edit /etc/fstab and add the nosuid option for all NFS file systems. Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54040r798812_chk'
  tag severity: 'medium'
  tag gid: 'V-250605'
  tag rid: 'SV-250605r798814_rule'
  tag stig_id: 'GEN005900-ESXI5-00891'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53994r798813_fix'
  tag 'documentable'
  tag legacy: ['V-39423', 'SV-51281']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
