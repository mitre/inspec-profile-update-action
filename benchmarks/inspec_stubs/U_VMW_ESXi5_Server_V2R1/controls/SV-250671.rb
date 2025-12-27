control 'SV-250671' do
  title 'The contents of exposed configuration files must be verified.'
  desc 'Although most configurations on ESXi are controlled via an API, there are a limited set of configuration files that are used directly to govern host behavior. These specific files are exposed via the vSphere HTTPS-based file transfer API. Any changes to these files should be correlated with an approved administrative action, such as an authorized configuration change. Tampering with these files has the potential to enable unauthorized access to the host configuration and virtual machines.  WARNING: do not attempt to monitor files that are NOT exposed via this file-transfer API, since this can result in a destabilized system.'
  desc 'check', 'ESXi Configuration files can be found by browsing to https://<hostname>/mob. 

A cryptographically hashed file integrity baseline is the best means to ensure these configuration files are preserved. 

Ask the SA if a cryptographically hashed file integrity baseline has been created and maintained for the system.

If no file integrity baseline exists for the system, this is a finding.

If the configuration files can be viewed with the MOB, this is a finding.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the host and run the following command(s): 

Determine if the MOB is enabled.
# vim-cmd proxysvc/service_list

If enabled, disable the MOB with the following command. 
# vim-cmd proxysvc/remove_service "/mob" "httpsWithRedirect"

NOTE: Some third-party tools use MOB to gather information. Testing should be done after disabling the MOB to verify third-party applications are still functioning as expected. To re-enable the MOB: 
# vim-cmd proxysvc/add_np_service "/mob" httpsWithRedirect".

Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54106r799010_chk'
  tag severity: 'medium'
  tag gid: 'V-250671'
  tag rid: 'SV-250671r799012_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000156'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54060r799011_fix'
  tag 'documentable'
  tag legacy: ['V-39350', 'SV-51208']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
