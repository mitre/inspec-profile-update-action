control 'SV-235857' do
  title 'Docker Enterprise registry certificate file ownership must be set to root:root.'
  desc '<0> [object Object]'
  desc 'check', 'Ensure that registry certificate file ownership is set to root:root.

Execute the below command to verify that the registry certificate files are owned and group-owned by root:

stat -c %U:%G /etc/docker/certs.d/*

If the certificate files are not owned by root, this is a finding.'
  desc 'fix', 'Set the ownership and group-ownership for the registry certificate files to root.

Run the following command:
chown root:root /etc/docker/certs.d/<registry-name>/*'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39076r627696_chk'
  tag severity: 'high'
  tag gid: 'V-235857'
  tag rid: 'SV-235857r627698_rule'
  tag stig_id: 'DKER-EE-005230'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39039r627697_fix'
  tag legacy: ['SV-104889', 'V-95751']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
