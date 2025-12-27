control 'SV-235794' do
  title 'The Docker Enterprise self-signed certificates in Docker Trusted Registry (DTR) must be replaced with DoD trusted, signed certificates.'
  desc 'Docker Enterprise includes the following capabilities that are considered non-essential:

*NOTE: disabling these capabilities negatively affects the operation of Universal Control Plane (UCP) and DTR and should be disregarded when UCP and DTR are installed. The security capabilities provided by UCP and DTR offset any potential vulnerabilities associated with not disabling these essential capabilities the Engine provides.

(Docker Engine - Enterprise: Standalone) - The majority of these items were originally identified as part of the CIS Docker Benchmark, which as of the CIS Docker Benchmark v1.2.0, are still applicable to Docker Engine - Enterprise 18.09
- inter-container communication (icc)* (CIS Docker Benchmark Recommendation 2.1)
- insecure registry communication (CIS Docker Benchmark Recommendation 2.4)
- AUFS storage driver (applicable on Linux only) (CIS Docker Benchmark Recommendation 2.5)
- listening on the TCP Daemon socket
- userland proxy for loopback traffic* (CIS Docker Benchmark Recommendation 2.15)
- experimental features (CIS Docker Benchmark Recommendation 2.17)
- Swarm Mode (CIS Docker Benchmark Recommendation 7.1)

(Docker Engine - Enterprise: As part of a UCP cluster)
- insecure registry communication (CIS Docker Benchmark Recommendation 2.4)
- AUFS storage driver (applicable on Linux only) (CIS Docker Benchmark Recommendation 2.5)
- listening on the TCP Daemon socket
- experimental features (CIS Docker Benchmark Recommendation 2.17)

(UCP)
- Managed user database
- self-signed certificates
- periodic usage reporting and API tracking
- allow users and administrators to schedule containers on all nodes, including UCP managers and DTR nodes

(DTR)
- periodic data usage/analytics reporting
- create repository on push
- self-signed certificates'
  desc 'check', 'Check that DTR has been integrated with a trusted certificate authority (CA).

via UI:

In the DTR web console, navigate to "System" | "General" and click on the "Show TLS settings" link in the "Domain & Proxies" section. Verify the certificate chain in "TLS Root CA" box is valid and matches that of the trusted CA.

via CLI:

Linux: Execute the following command and verify the certificate chain in the output is valid and matches that of the trusted CA:

echo "" | openssl s_client -connect [dtr_url]:443 | openssl x509 -noout -text

If the certificate chain in the output is not valid and does not match that of the trusted CA, then this is a finding.'
  desc 'fix', 'This fix only applies to the DTR component of Docker Enterprise.

Integrate DTR with a trusted CA.

via UI:

In the DTR web console, navigate to "System" | "General" and click on the "Show TLS Settings" link in the "Domain & Proxies" section. Fill in the "TLS Root CA" field with the contents of the external public CA certificate. Assuming the user generated a server certificate from that CA for DTR, also fill in the "TLS Certificate Chain" and "TLS Private Key" fields with the contents of the public/private certificates respectively. The "TLS Certificate Chain" field must include both the DTR server certificate and any intermediate certificates. Click on the "Save" button.

via CLI:

Linux: Execute the following command as a superuser on one of the UCP Manager nodes in the cluster:

docker run -it --rm docker/dtr:[dtr_version] reconfigure --dtr-ca "$(cat [ca.pem])" --dtr-cert "$(cat [dtr_cert.pem])" --dtr-key "$(cat [dtr_private_key.pem])"'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39013r627507_chk'
  tag severity: 'medium'
  tag gid: 'V-235794'
  tag rid: 'SV-235794r627509_rule'
  tag stig_id: 'DKER-EE-001880'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38976r627508_fix'
  tag 'documentable'
  tag legacy: ['SV-104759', 'V-95621']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
