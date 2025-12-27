control 'SV-80999' do
  title 'The Juniper SRX Services Gateway must ensure TCP forwarding is disabled for SSH to prevent unauthorized access.'
  desc 'Use this configuration option to prevent a user from creating an SSH tunnel over a CLI session to the Juniper SRX via SSH. This type of tunnel could be used to forward TCP traffic, bypassing any firewall filters or ACLs, allowing unauthorized access.'
  desc 'check', 'Use the CLI to view this setting for disabled for SSH. 

[edit]
show system services ssh

If TCP forwarding is not disabled for the root user, this is a finding.'
  desc 'fix', 'From the configuration mode, enter the following commands to disable TCP forwarding for the SSH protocol.

[edit]
set system services ssh no-tcp-forwarding'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67155r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66509'
  tag rid: 'SV-80999r1_rule'
  tag stig_id: 'JUSX-DM-000114'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-72583r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
