control 'SV-250583' do
  title 'Removable media, remote file systems, and any file system that does not contain approved setuid files must be mounted with the nosuid option.'
  desc 'The "nosuid" mount option causes the system to not execute setuid files with owner privileges. This option must be used for mounting any file system that does not contain approved setuid files. Executing setuid files from untrusted file systems, or file systems that do not contain approved setuid files, increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required. 
As root, log in to the host.  Check /etc/fstab and verify the nosuid mount option is used on file systems mounted from removable media, network shares, or any other file system not containing approved setuid or setgid files.

Each file system line entry must contain a device specific file and may additionally contain all of the following fields, in the following order (per the NFSv3 specification):
mount directory, type, OPTION(s), backup frequency, pass number (on parallel fsck) and comment.

Execute the following:
# cat /etc/fstab | grep -v "^#"

If the "nosuid" mount OPTION is not used on file systems mounted from removable media, network shares, or any other file system that does not contain approved setuid or setgid files, this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required. As root, log in to the host.  Edit /etc/fstab and add the nosuid mount option to all file systems mounted from removable media or network shares, and any file system not containing approved setuid or setgid files. Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54018r798746_chk'
  tag severity: 'medium'
  tag gid: 'V-250583'
  tag rid: 'SV-250583r798748_rule'
  tag stig_id: 'GEN002420-ESXI5-00878'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53972r798747_fix'
  tag 'documentable'
  tag legacy: ['V-39422', 'SV-51280']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
