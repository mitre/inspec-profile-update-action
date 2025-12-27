control 'SV-250542' do
  title 'The system must disable the autoexpand option for VDS dvPortgroups.'
  desc 'If the "no-unused-dvports" guideline is followed, there should be only the amount of ports on a VDS that are actually needed. The Autoexpand feature on VDS dvPortgroups can override that limit. The feature allows dvPortgroups to automatically add 10 virtual distributed switch ports to a dvPortgroup that has run out of available ports. The risk is that maliciously or inadvertently, a virtual machine that is not supposed to be part of that portgroup is able to affect confidentiality, integrity, or authenticity of data of other virtual machines on that portgroup. To reduce the risk of inappropriate dvPortgroup access, the autoexpand option on VDS should be disabled. By default the option is disabled, but regular monitoring must be implemented to verify this has not been changed.'
  desc 'check', 'If a vNetwork Distributed Switch (vDS) is not configured, this is not applicable.

Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

1. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
2. If connecting to vCenter Server, click on the desired host. 
3. Click the Configuration tab. 
4. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively.
5. Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and determine if the managed object browser (MOB) is enabled:
# vim-cmd proxysvc/service_list | grep proxy-mob

If the command return lists "proxy-mob", the mob is enabled. If not, re-enable the MOB: 
# vim-cmd proxysvc/add_np_service "/mob" httpsWithRedirect /var/run/vmware/proxy-mob
The autoexpand property is disabled by default, but it can be enabled using the MOB: 
1. In a browser, enter the address http://vc-ip-address/mob/. 
2. When prompted, enter the vCenter Server appropriate username and password. 
3. Click the Content link. 
4. In the left pane, search for the row with the word rootFolder. 
5. Open the link in the right pane of the row. The link should be similar to group-d1 (Datacenters).
6. In the left pane, search for the row with the word childEntity. In the right pane, you see a list of datacenter links.
7. Click the datacenter link in which the vDS is defined. 
8. In the left pane, search for the row with the word networkFolder and open the link in the right pane. The link should be similar to group-n123 (network).
9. In the left pane, search for the row with the word childEntity. You see a list of vDS and distributed port group links in the right pane.
10.Click the distributed port group for which you want to change this property.
11.In the left pane, search for the row with the word config and click the link in the right pane.
12.In the left pane, search for the row with the word autoExpand. It is usually the first row.
13.Note the corresponding value displayed in the right pane. The value should be false by default.

If the setting is true, the autoexpand feature is enabled and this is a finding.

Disable the MOB.
# vim-cmd proxysvc/remove_service "/mob" "httpsWithRedirect"

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

1. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
2. If connecting to vCenter Server, click on the desired host. 
3. Click the Configuration tab. 
4. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively.
5. Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and determine if the managed object browser (MOB) is enabled:
# vim-cmd proxysvc/service_list | grep proxy-mob

If the command return lists "proxy-mob", the mob is enabled. If not, re-enable the MOB: 
# vim-cmd proxysvc/add_np_service "/mob" httpsWithRedirect /var/run/vmware/proxy-mob

The autoexpand property is disabled by default, but it can be enabled using the MOB: 
1. In a browser, enter the address http://vc-ip-address/mob/. 
2. When prompted, enter the vCenter Server appropriate username and password. 
3. Click the Content link. 
4. In the left pane, search for the row with the word rootFolder. 
5. Open the link in the right pane of the row. The link should be similar to group-d1 (Datacenters).
6. In the left pane, search for the row with the word childEntity. In the right pane, you see a list of datacenter links.
7. Click the datacenter link in which the vDS is defined. 
8. In the left pane, search for the row with the word networkFolder and open the link in the right pane. The link should be similar to group-n123 (network).
9. In the left pane, search for the row with the word childEntity. You see a list of vDS and distributed port group links in the right pane.
10.Click the distributed port group for which you want to change this property.
11.In the left pane, search for the row with the word config and click the link in the right pane.
12.In the left pane, search for the row with the word autoExpand. It is usually the first row.
13.Note the corresponding value displayed in the right pane. The value should be false by default.
14. In the left pane, search for the row with the word configVersion. The value should be 1 only if it has not been previously modified.
15. Note the corresponding value displayed in the right pane as it is needed in step 18.
16. Go back to the distributed port group page. 
17. Click the link that reads ReconfigureDvs_Task. A new window appears. 
18. In the Spec text field, enter this text:

<spec><autoExpand>false</autoExpand><configversion>configVersion</configversion></spec>

where configVersion is what was recorded directly above in step 15.

19. Click the Invoke Method link. 
20. Close the window. 
21. Repeat Steps 10 through 14 to verify the new value for autoExpand.

Disable the MOB.
# vim-cmd proxysvc/remove_service "/mob" "httpsWithRedirect"

Re-enable Lockdown Mode on the host.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53977r798623_chk'
  tag severity: 'low'
  tag gid: 'V-250542'
  tag rid: 'SV-250542r798625_rule'
  tag stig_id: 'ESXI5-VMNET-000026'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53931r798624_fix'
  tag 'documentable'
  tag legacy: ['SV-51238', 'V-39380']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
