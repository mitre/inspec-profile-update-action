control 'SV-235841' do
  title 'Universal Control Plane (UCP) must be integrated with a trusted certificate authority (CA) in Docker Enterprise.'
  desc 'Both the UCP and Docker Trusted Registry (DTR) components of Docker Enterprise leverage the same authentication and authorization backplane known as eNZi. The eNZi backplane includes its own managed user database, and also allows for LDAP integration in UCP and DTR. To meet the requirements of this control, configure LDAP integration. UCP also includes two certificate authorities for establishing root of trust. One CA is used to sign client bundles and the other is used for TLS communication between UCP components and nodes. Both of these CAs should be integrated with an external, trusted CA. DTR should be integrated with this same external, trusted CA as well.'
  desc 'check', 'This check only applies to the UCP component of Docker Enterprise.

Check that UCP has been integrated with a trusted CA.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Certificates" and click on the "Download UCP Server CA Certificate" link. Verify that the contents of the downloaded "ca.pem" file match that of the trusted CA certificate.

If the certificate chain is not valid or does not match the trusted CA, this is a finding.

via CLI:

Linux: Execute the following command and verify the certificate chain in the output is valid and matches that of the trusted CA:

echo "" | openssl s_client -connect [ucp_url]:443 | openssl x509 -noout -text

If the certificate chain is not valid or does not match the trusted CA, this is a finding.'
  desc 'fix', %q(This fix only applies to the UCP component of Docker Enterprise.

Integrate UCP with a trusted CA.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Certificates". Fill in (or click on the "Upload" links) the "CA Certificate" field with the contents of your public CA certificate. Assuming the user has generated a server certificate from that CA for UCP, also fill in the "Server Certificate" and "Private Key" fields with the contents of the public/private certificates respectively. The "Server Certificate" field must include both the UCP server certificate and any intermediate certificates. Click on the "Save" button.

If DTR was previously integrated with this UCP cluster, execute a "dtr reconfigure" command as a superuser on one of the UCP Manager nodes in the cluster to re-configure DTR with the updated UCP certificates.

via CLI:
Linux : As a superuser, execute the following commands on each UCP Manager node in the cluster and in the directory where keys and certificates are stored:

Create a container that attaches to the same volume where certificates are stored:

docker create --name replace-certs -v ucp-controller-server-certs:/data busybox

Copy keys and certificates to the container's volumes:

docker cp cert.pem replace-certs:/data/cert.pem
docker cp ca.pem replace-certs:/data/ca.pem
docker cp key.pem replace-certs:/data/key.pem

Remove the container, since it is no longer needed:

docker rm replace-certs

Restart the container, since it is no longer needed:

docker rm replace-certs

Restart the ucp-controller container:

docker restart ucp-controller

If DTR was previously integrated with this UCP cluster, execute a "dtr reconfigure" command as a superuser on one of the UCP Manager nodes in the cluster to re-configure DTR with the updated UCP certificates.)
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39060r627648_chk'
  tag severity: 'medium'
  tag gid: 'V-235841'
  tag rid: 'SV-235841r627650_rule'
  tag stig_id: 'DKER-EE-003920'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-39023r627649_fix'
  tag 'documentable'
  tag legacy: ['SV-104853', 'V-95715']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
