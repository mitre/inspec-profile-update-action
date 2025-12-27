control 'SV-250672' do
  title 'Unauthorized kernel modules must not be loaded on the host.'
  desc 'VMware provides digital signatures for kernel modules.  By default the ESXi host does not permit loading of kernel modules that lack a valid digital signature.  However, this behavior can be overridden allowing unauthorized kernel modules to be loaded.  Untested or  malicious kernel modules loaded onto an ESXi host can put the host at risk for instability and/or exploitation. The ESXi host must be monitored for unsigned kernel modules.'
  desc 'check', %q(Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required. As root, log in to and inspect the host for unsigned kernel modules. To list all the loaded kernel modules run: 
# esxcli system module list

For each host module verify the signature by running:
# esxcli system module get -m <module>"

Note that the integrity of unsigned third party kernel modules and modules with inadvertently omitted digital signatures (by VMware) can still be verified using the digital signature of the vSphere Installation Bundle (VIB) originally used to install the software. If the host's module list contains any unsigned modules, check the acceptance level for all installed VIBs via the following ESXCLI command:
# esxcli software vib list

If the host's installed kernel module/VIB digital signatures cannot be determined, this is a finding.

Re-enable Lockdown Mode on the host.)
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively. Start the ESXi Shell service, where/as required. As root, log in to and secure the host by individually disabling unsigned modules and removing the offending VIBs from the host. Note that in order to disable kernel modules, from the vSphere Client, VMs must first be evacuated and the host must then be placed into maintenance mode.
# esxcli system modules set -e false -m <module>

Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54107r799013_chk'
  tag severity: 'medium'
  tag gid: 'V-250672'
  tag rid: 'SV-250672r799015_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000158'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54061r799014_fix'
  tag 'documentable'
  tag legacy: ['SV-51209', 'V-39351']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
