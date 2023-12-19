control 'SV-243120' do
  title 'The vCenter Server must have Mutual CHAP configured for vSAN iSCSI targets.'
  desc 'When Mutual CHAP is enabled, vSphere performs bidirectional authentication of both the iSCSI target and host. There is a potential for a MitM attack when not authenticating both the iSCSI target and host in which an attacker might impersonate either side of the connection to steal data. Bidirectional authentication mitigates this risk.'
  desc 'check', 'If no clusters are enabled for vSAN or if vSAN is enabled but iSCSI is not enabled, this is not applicable.

From the vSphere Client, go to Hosts and Clusters >> select a vSAN Enabled Cluster >> Configure >> vSAN >> iSCSI Target Service.

For each iSCSI target, review the value in the "Authentication" column.

If the Authentication method is not set to "CHAP_Mutual" for any iSCSI target, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters >> select a vSAN Enabled Cluster >> Configure >> vSAN >> iSCSI Target Service.

For each iSCSI target, select the item and click "Edit". 

Change the "Authentication" field to "Mutual CHAP" and configure the incoming and outgoing users and secrets appropriately.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46395r719601_chk'
  tag severity: 'medium'
  tag gid: 'V-243120'
  tag rid: 'SV-243120r879887_rule'
  tag stig_id: 'VCTR-67-000065'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46352r719602_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
