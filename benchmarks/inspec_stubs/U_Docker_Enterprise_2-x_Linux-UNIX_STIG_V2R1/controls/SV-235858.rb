control 'SV-235858' do
  title 'Docker Enterprise registry certificate file permissions must be set to 444 or more restrictive.'
  desc '<0> [object Object]'
  desc 'check', 'Ensure that registry certificate file permissions are set to 444 or more restrictive.

Execute the below command to verify that the registry certificate files have permissions of 444 or more restrictive:

stat -c %a /etc/docker/certs.d/<registry-name>/*

If the permissions are not set to 444, this is a finding.'
  desc 'fix', 'Set the permissions for registry certificate files to 444.

Run the following command:
chmod 444 /etc/docker/certs.d/<registry-name>/*'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39077r627699_chk'
  tag severity: 'medium'
  tag gid: 'V-235858'
  tag rid: 'SV-235858r627701_rule'
  tag stig_id: 'DKER-EE-005240'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39040r627700_fix'
  tag legacy: ['SV-104891', 'V-95753']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
