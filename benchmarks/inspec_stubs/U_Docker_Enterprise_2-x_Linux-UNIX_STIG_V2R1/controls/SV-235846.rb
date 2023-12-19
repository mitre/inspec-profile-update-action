control 'SV-235846' do
  title 'Only trusted, signed images must be stored in Docker Trusted Registry (DTR) in Docker Enterprise.'
  desc 'The Universal Control Plane (UCP) and DTR components of Docker Enterprise can be used in concert to perform an integrity check of organization-defined software at startup. In the context of Docker Enterprise, software would be analogous to Docker images that have been pulled from trusted or untrusted sources. Docker Hub is the most common upstream endpoint for retrieving Docker images. However, only "Docker Certified" images on Docker Hub are considered trusted and come with SLAs and trusted signatures from their respective vendors. All other images from Docker Hub or other external registries must be carefully inspected and triaged prior to use. Docker Content Trust (DCT) provides for content integrity checking mechanisms on Docker images. DCT can be combined with LDAP, DTR and UCP to enforce image signatures from users/accounts in LDAP. Therefore, to meet the requirements of this control, it is imperative that UCP has LDAP integration enabled and that content trust enforcement is enabled and properly configured.

'
  desc 'check', %q(This check only applies to the DTR component of Docker Enterprise.

Verify that all images that are stored in DTR are trusted, signed images:

via UI: As a Docker EE Admin, navigate to "Repositories" in the DTR management console. Select a repository from the list. Navigate to the "Images" tab and verify that the "Signed" checkmark is indicated for each image tag. Repeat this for all repositories stored in DTR.

If images stored in DTR are not signed, this is a finding.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands on a machine that can communicate with the DTR management console. Replace [dtr_url] with the DTR URL, [dtr_username] with the username of a Docker EE Admin and [dtr_password] with the password of a Docker EE Admin.

AUTHTOKEN=$(curl -sk -u [dtr_username]:[dtr_password] -X GET "https://[dtr_url]/auth/token" | jq -r .token)
REPOS=$(curl -sk -H "Authorization: Bearer $AUTHTOKEN" -X GET "https://[dtr_url]/api/v0/repositories" | jq -r '.repositories[] | "\(.namespace)/\(.name)"')
for r in $REPOS; do curl -sk -H "Authorization: Bearer $AUTHTOKEN" -X GET "https://[dtr_url]/api/v0/repositories/$r/tags?domain=[dtr_url]"; done | jq -r '.[] | [.name, .inNotary] | @csv'

Verify that "true" is output next to all tags listed.

If all images stored in DTR are not signed and trusted, this is a finding.)
  desc 'fix', 'This fix only applies to the DTR component of Docker Enterprise.

Store only trusted, signed images in DTR.

via CLI:

Linux: Execute the following commands as a user with access to the repository in DTR for which image signing is being enabled:

docker login [dtr_url]
docker trust signer add --key [ucp_client_bundle_cert].pem [ucp_user] [dtr_url]/[namespace]/[imageName]
docker trust key load [ucp_client_bundle_key].pem
docker tag [source_image] [dtr_url]/[namespace]/[imageName]:[tag]
export DOCKER_CONTENT_TRUST=1
docker push [dtr_url]/[namespace]/[imageName]:[tag]'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39065r627663_chk'
  tag severity: 'medium'
  tag gid: 'V-235846'
  tag rid: 'SV-235846r627665_rule'
  tag stig_id: 'DKER-EE-004260'
  tag gtitle: 'SRG-APP-000475'
  tag fix_id: 'F-39028r627664_fix'
  tag satisfies: ['SRG-APP-000475', 'SRG-APP-000480', 'SRG-APP-000484', 'SRG-APP-000485', 'SRG-APP-000386']
  tag 'documentable'
  tag legacy: ['SV-104865', 'V-95727']
  tag cci: ['CCI-001774', 'CCI-002710', 'CCI-002715', 'CCI-002723', 'CCI-002724']
  tag nist: ['CM-7 (5) (b)', 'SI-7 (1)', 'SI-7 (5)', 'SI-7 (8)', 'SI-7 (8)']
end
