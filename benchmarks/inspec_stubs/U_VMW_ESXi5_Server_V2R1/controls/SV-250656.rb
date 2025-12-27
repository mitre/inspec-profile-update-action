control 'SV-250656' do
  title 'The system must disable the Managed Object Browser (MOB).'
  desc 'The Managed Object Browser (MOB) provides a way to explore the object model used by the VMkernel to manage the host and enables configurations to be changed as well. This interface is meant to be used primarily for debugging the vSphere SDK, but because there are no access controls it could also be used as a method obtain information about a host being targeted for unauthorized access.'
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and determine if the MOB is enabled.
# vim-cmd proxysvc/service_list | grep proxy-mob

If the command return lists "proxy-mob", this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and disable the MOB.
# vim-cmd proxysvc/remove_service "/mob" "httpsWithRedirect". 

Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54091r798965_chk'
  tag severity: 'medium'
  tag gid: 'V-250656'
  tag rid: 'SV-250656r798967_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000137'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54045r798966_fix'
  tag 'documentable'
  tag legacy: ['SV-51112', 'V-39296']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
