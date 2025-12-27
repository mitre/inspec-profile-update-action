control 'SV-216889' do
  title 'The vCenter Server for Windows must disable SNMPv1.'
  desc 'SNMPv3 supports commercial-grade security, including authentication, authorization, access control, and privacy while previous versions of the protocol contained well-known security weaknesses that were easily exploited. SNMPv3 can be configured for identification and cryptographically based authentication. 

SNMPv3 is not supported in vCenter Server for Windows.'
  desc 'check', 'NOTE: For the vCenter 6.5 Server Appliance, this requirement is Not Applicable.

In the vSphere Web Client go to a vCenter Server instance.
Click the Configure tab >> Settings >> General.
On the vCenter Server Settings central pane, click Edit.
Click SNMP receivers to edit their settings.
Ensure no information for SNMP receivers are entered.  If there are SNMP receivers configured, this is a finding.'
  desc 'fix', 'In the vSphere Web Client go to a vCenter Server instance.
Click the Configure tab >> Settings >> General.
On the vCenter Server Settings central pane, click Edit.
Click SNMP receivers to edit their settings.
Remove any SNMP receivers that exist.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18120r366381_chk'
  tag severity: 'medium'
  tag gid: 'V-216889'
  tag rid: 'SV-216889r612237_rule'
  tag stig_id: 'VCWN-65-006000'
  tag gtitle: 'SRG-APP-000575'
  tag fix_id: 'F-18118r366382_fix'
  tag 'documentable'
  tag legacy: ['V-94853', 'SV-104683']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
