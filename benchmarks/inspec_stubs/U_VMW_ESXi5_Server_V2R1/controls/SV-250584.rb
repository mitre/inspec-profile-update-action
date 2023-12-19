control 'SV-250584' do
  title 'Removable media, remote file systems, and any file system that does not contain approved device files must be mounted with the nodev option.'
  desc 'The "nodev" (or equivalent) mount option causes the system to not handle device files as system devices. This option must be used for mounting any file system that does not contain approved device files. Device files can provide direct access to system hardware and can compromise security if not protected.'
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required. 

As root, log in to the host.  Check the system for NFS mounts that do not use the nodev option. Execute the following:
#  cat /etc/fstab | grep -i nfs | grep -v "nodev"

If the mounted NFS file systems do not use the nodev option, this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required. As root, log in to the host.  Edit /etc/fstab and add the nodev option for all NFS file systems. Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54019r798749_chk'
  tag severity: 'medium'
  tag gid: 'V-250584'
  tag rid: 'SV-250584r798751_rule'
  tag stig_id: 'GEN002430-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53973r798750_fix'
  tag 'documentable'
  tag legacy: ['SV-51239', 'V-39381']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
