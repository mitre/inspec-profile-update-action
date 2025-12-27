control 'SV-251239' do
  title 'Redis Enterprise DBMS must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.'
  desc 'Only DoD-approved external PKIs have been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.'
  desc 'check', 'Redis Enterprise Software (RS) can use industry-standard encryption to protect data in transit between a Redis client and RS. For this purpose, RS uses transport layer security (TLS) protocol.

Run the following commands and verify certificates are present:
# cd /etc/opt/redislabs
# ls 

Verify that all present certificates are issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).

If non DoD-approved PKI certificates are found, this is a finding.

Verify TLS is configured to be used. To check this:
1. Log in to the Redis Enterprise web UI as an admin user.
2. Navigate to the Databases tab and select the database and then configuration.
3. Review the configuration and verify that TLS is enabled for all communications.

If TLS is not configured to be used, this is a finding.

To check the current TLS version, run the following commands on one of the servers that is hosting Redis Enterprise as a privileged user:
# ccs-cli
# hgetall min_control_tls_version

If TLS is not FIPS 140-2 compliant, this is a finding.'
  desc 'fix', %q(rladmin CLI or the REST API may be used to update the certificates.

Using the CLI: 
To replace certificates using the rladmin CLI, run:
 rladmin cluster certificate set <cert-name> certificate_file <cert-file-name>.pem key_file <key-file-name>.pem
Where:
cert-name - The name of certificate to be replaced:
For management UI: cm
For REST API: api
For database endpoint: proxy
For syncer: syncer
For metrics exporter: metrics_exporter
cert-file-name - The name of the certificate file
key-file-name - The name of the key file

For example, to replace the cm certificate with the private key "key.pem" and the certificate file "cluster.pem":
rladmin cluster certificate set cm certificate_file cluster.pem key_file key.pem

To replace a certificate using the REST API, run:
curl -k -X PUT -u "<username>:<password>" -H "Content-Type: application/json" -d '{ "name": "<cert_name>", "key": "<key>", "certificate": "<cert>" }' https://<cluster_address>:9443/v1/cluster/update_cert
Where:
cert_name - The name of the certificate to replace:
For management UI: cm
For REST API: api
For database endpoint: proxy
For syncer: syncer
For metrics exporter: metrics_exporter
key - The contents of the *_key.pem file
cert - The contents of the *_cert.pem file

When upgrading RS, the upgrade process copies the certificates on the first upgraded node to all of the nodes in the cluster.

Tip: The key file contains \n end of line characters (EOL) that cannot be pasted into the API call. Use sed -z 's/\n/\\\n/g' to escape the EOL characters.)
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54674r804905_chk'
  tag severity: 'medium'
  tag gid: 'V-251239'
  tag rid: 'SV-251239r804907_rule'
  tag stig_id: 'RD6X-00-010500'
  tag gtitle: 'SRG-APP-000427-DB-000385'
  tag fix_id: 'F-54628r804906_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
