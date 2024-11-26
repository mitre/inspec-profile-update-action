control 'SV-216884' do
  title 'The vCenter Server for Windows must have Mutual CHAP configured for vSAN iSCSI targets.'
  desc 'When enabled vSphere performs bidirectional authentication of both the iSCSI target and host. There is a potential for a MitM attack when not authenticating both the iSCSI target and host in which an attacker might impersonate either side of the connection to steal data. Bidirectional authentication mitigates this risk.'
  desc 'check', 'If no clusters are enabled for vSAN or if vSAN is enabled but iSCSI is not enabled, this is not applicable.

From the vSphere Web Client go to Host and Clusters >> Select a Cluster >> Configure >> Virtual SAN >> iSCSI Targets

For each iSCSI Target select the item and click the pencil icon to open the edit dialog. 

If the Authentication method is not set to "Mutual CHAP" and fully configured, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Host and Clusters >> Select a Cluster >> Configure >> Virtual SAN >> iSCSI Targets

For each iSCSI Target select the item and click the pencil icon to open the edit dialog. Change the "Authentication" field to "Mutual CHAP" and configure the incoming and outgoing users and secrets appropriately.'
  impact 0.3
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18115r366366_chk'
  tag severity: 'low'
  tag gid: 'V-216884'
  tag rid: 'SV-216884r612237_rule'
  tag stig_id: 'VCWN-65-000065'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18113r366367_fix'
  tag 'documentable'
  tag legacy: ['SV-104663', 'V-94833']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
