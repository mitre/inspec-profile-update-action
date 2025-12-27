control 'SV-235842' do
  title 'Docker Trusted Registry (DTR) must be integrated with a trusted certificate authority (CA) in Docker Enterprise.'
  desc 'Both the Universal Control Plane (UCP) and DTR components of Docker Enterprise leverage the same authentication and authorization backplane known as eNZi. The eNZi backplane includes its own managed user database, and also allows for LDAP integration in UCP and DTR. To meet the requirements of this control, configure LDAP integration. UCP also includes two certificate authorities for establishing root of trust. One CA is used to sign client bundles and the other is used for TLS communication between UCP components and nodes. Both of these CAs should be integrated with an external, trusted CA. DTR should be integrated with this same external, trusted CA as well.'
  desc 'check', 'This check only applies to the DTR component of Docker Enterprise.

Check that DTR has been integrated with a trusted CA.

via UI:

In the DTR web console, navigate to "System" | "General" and click on the "Show TLS settings" link in the "Domain & Proxies" section. Verify the certificate chain in "TLS Root CA" box is valid and matches that of the trusted CA.

via CLI:

Linux: Execute the following command and verify the certificate chain in the output is valid and matches that of the trusted CA:

echo "" | openssl s_client -connect [dtr_url]:443 | openssl x509 -noout -text

If the certificate chain is not valid or does not match the trusted CA, this is a finding.'
  desc 'fix', 'This fix only applies to the DTR component of Docker Enterprise.

Integrate DTR with a trusted CA.

via UI:

In the DTR web console, navigate to "System" | "General" and click on the "Show TLS Settings" link in the "Domain & Proxies" section. Fill in the "TLS Root CA" field with the contents of the trusted CA certificate. Assuming the user has generated a server certificate from that CA for DTR, also fill in the "TLS Certificate Chain" and "TLS Private Key" fields with the contents of the public/private certificates respectively. The "TLS Certificate Chain" field must include both the DTR server certificate and any intermediate certificates. Click on the "Save" button.

via CLI:

Linux: Execute the following command as a superuser on one of the UCP Manager nodes in the cluster:

docker run -it --rm docker/dtr:[dtr_version] reconfigure --dtr-ca "$(cat [ca.pem])" --dtr-cert "$(cat [dtr_cert.pem])" --dtr-key "$(cat [dtr_private_key.pem])"'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39061r627651_chk'
  tag severity: 'medium'
  tag gid: 'V-235842'
  tag rid: 'SV-235842r627653_rule'
  tag stig_id: 'DKER-EE-003930'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-39024r627652_fix'
  tag 'documentable'
  tag legacy: ['SV-104857', 'V-95719']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
