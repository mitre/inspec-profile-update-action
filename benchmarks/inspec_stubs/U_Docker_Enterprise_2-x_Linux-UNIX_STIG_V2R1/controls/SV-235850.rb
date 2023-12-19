control 'SV-235850' do
  title 'Docker Enterprise node certificates must be rotated as defined in the System Security Plan (SSP).'
  desc 'Rotate swarm node certificates as appropriate.

Docker Swarm uses mutual TLS for clustering operations amongst its nodes. Certificate rotation ensures that in an event such as compromised node or key, it is difficult to impersonate a node. By default, node certificates are rotated every 90 days. The user should rotate it more often or as appropriate in their environment.

By default, node certificates are rotated automatically every 90 days.'
  desc 'check', 'Ensure node certificates are rotated as appropriate.

via CLI:

Linux: As a Docker EE Admin, follow the steps below using a Universal Control Plane (UCP) client bundle:

Run the below command and ensure that the node certificate Expiry Duration is set according to the System Security Plan (SSP).

docker info | grep "Expiry Duration"

If the expiry duration is not set according to the SSP, this is a finding.'
  desc 'fix', 'Run the below command to set the desired expiry time.

Example:
docker swarm update --cert-expiry 48h'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39069r627675_chk'
  tag severity: 'medium'
  tag gid: 'V-235850'
  tag rid: 'SV-235850r627677_rule'
  tag stig_id: 'DKER-EE-005080'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39032r627676_fix'
  tag 'documentable'
  tag legacy: ['SV-104873', 'V-95735']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
