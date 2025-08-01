control 'SV-16750' do
  title 'Unused port groups have not been removed'
  desc 'Port groups define how virtual machine connections are made through the virtual switch.  Port groups may be configured with bandwidth limitations and VLAN tagging policies for each member port. Multiple ports may be aggregated under port groups to provide a local point for virtual machines to connect to a network. The maximum number of port groups that may be configured on a virtual switch is 512. Each port group is identified by a network label and a VLAN ID.  As with any physical switch, all unused virtual switch port groups will be removed if not in use.  Physical switches place these unused ports in unused VLANs and shutdown the port.  For the ESX Server, these port groups must be removed to ensure that they are not used by mistake.'
  desc 'check', 'Work with the system administrator to gain access to the ESX Server service console to perform 
the following command.

# esxcfg-vswitch –l
 
If the ‘Used Ports’ has the number 0, this is a finding. 

Caveat: VMotion, HA, and DRS virtual switches may have unused port groups.  This check is not applicable to these switches. Also, if VMotion is configured for a virtual machine(s), then when VMotion occurs, a duplicate virtual switch will be configured so the virtual machine can run once the migration is complete.  These virtual switches will have 0 used ports until it is VMotioned to the ESX Server host.  Therefore, virtual switches in this scenario are not applicable to this check. These virtual switches must be available for proper VMotion, HA, and DRS purposes.'
  desc 'fix', 'Remove all unused port groups from virtual switches.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16077r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15811'
  tag rid: 'SV-16750r1_rule'
  tag stig_id: 'ESX0220'
  tag gtitle: 'ESX0220'
  tag fix_id: 'F-15764r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECSC-1'
end
