control 'SV-250668' do
  title 'Keys from SSH authorized_keys file must be removed.'
  desc %q(ESXi hosts come with SSH which can be enabled to allow remote access without requiring user authentication. To enable password free access copy the remote users public key into the "/etc/ssh/keys-root/authorized_keys" file on the ESXi host. The presence of the remote user's public key in the "authorized_keys" file identifies the user as trusted, meaning the user is granted access to the host without providing a password. Note:  Lockdown mode does not apply to root users who log in using authorized keys. When you use an authorized key file for root user authentication, root users are not prevented from accessing a host with SSH even when the host is in lockdown mode.)
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client.

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the host and verify the /etc/ssh/keys-root/authorized_keys file does not exist or is empty (zero bytes): 
# ls -l /etc/ssh/keys-root/authorized_keys

If the authorized_keys file exists and is not empty, this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the host and zero/remove /etc/ssh/keys-root/authorized_keys file: 
# >/etc/ssh/keys-root/authorized_keys
or
# rm /etc/ssh/keys-root/authorized_keys

Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54103r799001_chk'
  tag severity: 'medium'
  tag gid: 'V-250668'
  tag rid: 'SV-250668r799003_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000152'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54057r799002_fix'
  tag 'documentable'
  tag legacy: ['SV-51205', 'V-39347']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
