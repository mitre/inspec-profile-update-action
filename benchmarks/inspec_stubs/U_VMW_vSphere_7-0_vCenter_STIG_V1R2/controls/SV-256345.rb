control 'SV-256345' do
  title 'The vCenter server must disable SNMPv1/2 receivers.'
  desc 'SNMPv3 supports commercial-grade security, including authentication, authorization, access control, and privacy. Previous versions of the protocol contained well-known security weaknesses that were easily exploited. Therefore, SNMPv1/2 receivers must be disabled, while SNMPv3 is configured in another control. vCenter exposes SNMP v1/2 in the UI and SNMPv3 in the CLI.'
  desc 'check', 'From the vSphere Client, go to Host and Clusters.

Select a vCenter Server >> Configure >> Settings >> General.

Click "Edit".

On the "SNMP receivers" tab, note the presence of any enabled receiver.

If there are any enabled receivers, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Host and Clusters.

Select a vCenter Server >> Configure >> Settings >> General.

Click "Edit".

On the "SNMP receivers" tab, ensure all receivers are disabled.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCenter'
  tag check_id: 'C-60020r885644_chk'
  tag severity: 'medium'
  tag gid: 'V-256345'
  tag rid: 'SV-256345r885646_rule'
  tag stig_id: 'VCSA-70-000265'
  tag gtitle: 'SRG-APP-000575'
  tag fix_id: 'F-59963r885645_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
