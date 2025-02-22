control 'SV-16731' do
  title 'Static discoveries are not configured for hardware iSCSI initiators.'
  desc 'ESX Server uses two types of methods to determine what storage resources are available for access by the iSCSI initiators on the network. These methods are dynamic discovery and static discovery. With dynamic discovery, the initiator discovers iSCSI targets by sending a SendTargets request to a specified target address. The target device responds by forwarding a list of additional targets that the initiator is allowed to access. The static discovery method uses the SendTargets request and returned is the list of available targets. Targets are listed on the static discovery list. This list may be modified by the storage administrator by adding or removing targets. The static discovery method is available only with the hardware-initiated storage. Hardware iSCSI initiators will use static discovery since it reduces the likelihood of connecting to some rogue target since all the targets are defined in the static list.'
  desc 'check', 'This check only applies if hardware iSCSI initiators are used.  If they are used, then perform the 
following steps to verify static discovery is being used.
1. Log into VirtualCenter with the VI Client and select a ESX server from the inventory panel.
2. Click the Configuration tab and click Storage Adapters in the Hardware group.
    The list of available adapters (initiators) appears.  The iSCSI initiator appears in the list of storage adapters. 
3.  Under HBA, choose the initiator to review.
4.  Click Properties, and the click the Static Discovery tab to verify that iSCSI targets are configured.  If none are configured, this is a finding.
5.  Next verify that the dynamic discovery tab has no listings.  If it does, this is a finding.'
  desc 'fix', 'Configure hardware initiators to use static discovery only.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-15979r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15792'
  tag rid: 'SV-16731r1_rule'
  tag stig_id: 'ESX0100'
  tag gtitle: 'Static discoveries not used for iSCSI initiators.'
  tag fix_id: 'F-15734r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
