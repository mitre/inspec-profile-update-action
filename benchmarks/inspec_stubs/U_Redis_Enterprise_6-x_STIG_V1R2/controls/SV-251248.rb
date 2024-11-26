control 'SV-251248' do
  title 'Redis Enterprise DBMS must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.

When transmitting data, the DBMS, associated applications, and infrastructure must leverage transmission protection mechanisms.

For more detailed information, refer to:
https://docs.redislabs.com/latest/rs/administering/designing-production/security/'
  desc 'check', 'Redis has optional support for TLS on all communication channels, including client connections, replication links, and the Redis Cluster bus protocol.

By default, each cluster node has a different set of self-signed certificates. These certificates can be replaced with a DoD-acceptable certificate, preferably a certificate issued by an intermediate certificate authority (CA).

For security reasons, Redis Enterprise only supports only the TLS protocol. Therefore, verify that the Redis client or secured tunnel solution is TLS v1.2 or above.

First, verify that the host operating system is encrypted. 

If the host operating system is not encrypted, this is a finding.

If the host operating system is encrypted, run the following commands and verify that only DoD-approved PKI certificates are present:
# cd /etc/opt/redislabs
# ls 

Verify the proxy_cert.pem file is present.

If no certificates are found, this is a finding.

Verify that TLS is configured to be used. To check this:
1. Log in to the Redis Enterprise web UI as an admin user.
2. Navigate to the Databases tab and select the database and then configuration.
3. Review the configuration and verify that TLS is enabled for all communications.

If TLS is not configured to be used, this is a finding.

To check the current TLS version, run the following commands on one of the servers that is hosting Redis Enterprise as a privileged user:
# ccs-cli
# hgetall min_control_tls_version

If TLS is not FIPS compliant, this is a finding.'
  desc 'fix', 'To configure TLS and configure only organizationally defined CA-signed certificates, refer to the following document: 
https://docs.redislabs.com/latest/rs/administering/cluster-operations/updating-certificates/'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54683r863374_chk'
  tag severity: 'medium'
  tag gid: 'V-251248'
  tag rid: 'SV-251248r863375_rule'
  tag stig_id: 'RD6X-00-011600'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-54637r804933_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
