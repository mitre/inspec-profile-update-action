control 'SV-235849' do
  title 'Docker Enterprise Swarm manager auto-lock key must be rotated periodically.'
  desc 'Rotate swarm manager auto-lock key periodically.

Swarm manager auto-lock key is not automatically rotated. Rotate them periodically as a best practice.

By default, keys are not rotated automatically.'
  desc 'check', 'Interview the system administrator to identify the key rotation process. Determine if there is a key rotation record and if the keys are rotated at a pre-defined frequency.

If the swarm manager auto-lock key is not rotated on a regular basis, this is a finding.'
  desc 'fix', 'Run the below command to rotate the keys.

docker swarm unlock-key --rotate

Additionally, to facilitate audit for this recommendation, maintain key rotation records and ensure that a pre-defined frequency for key rotation is established.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39068r627672_chk'
  tag severity: 'medium'
  tag gid: 'V-235849'
  tag rid: 'SV-235849r627674_rule'
  tag stig_id: 'DKER-EE-005070'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39031r627673_fix'
  tag 'documentable'
  tag legacy: ['SV-104871', 'V-95733']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
