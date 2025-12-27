control 'SV-251237' do
  title 'Redis Enterprise DBMS must recognize only system-generated session identifiers.'
  desc 'This requirement focuses on communications protection for the DBMS session rather than for the network packet. The intent of this control is to establish grounds for confidence at each end of a communications session in the ongoing identity of the other party and in the validity of the information being transmitted. 

Redis Enterprise Software (RS) uses self-signed certificates out-of-the-box to make sure that sessions are secure by default. When using the default self-signed certificates, an untrusted connection notification is shown in the web UI. Depending on the browser used, the user can allow the connection for each session or add an exception to make the site trusted in future sessions.'
  desc 'check', 'By default, each cluster node has a different set of self-signed certificates. These certificates can be replaced with a DoD-acceptable certificate, preferably a certificate issued by an intermediate certificate authority (CA).

For security reasons, Redis Enterprise only supports the TLS protocol. Therefore, verify that the Redis client or secured tunnel solution is TLS v1.2 or above.

Run the following commands and verify that certificates are present:
# cd /etc/opt/redislabs
# ls 

Verify the proxy_cert.pem file is present.

If no certificates are present, this is a finding.'
  desc 'fix', 'To configure TLS and configure only organizationally defined CA-signed certificates, refer to the following document: 
https://docs.redislabs.com/latest/rs/administering/cluster-operations/updating-certificates/'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54672r804899_chk'
  tag severity: 'medium'
  tag gid: 'V-251237'
  tag rid: 'SV-251237r804901_rule'
  tag stig_id: 'RD6X-00-010300'
  tag gtitle: 'SRG-APP-000223-DB-000168'
  tag fix_id: 'F-54626r804900_fix'
  tag 'documentable'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
