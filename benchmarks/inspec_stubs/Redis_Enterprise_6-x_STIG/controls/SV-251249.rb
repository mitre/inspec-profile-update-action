control 'SV-251249' do
  title 'Redis Enterprise DBMS must maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

This requirement applies only to those applications that are either distributed or can allow access to data nonlocally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When receiving data, the DBMS, associated applications, and infrastructure must leverage protection mechanisms.'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.

If Redis Enterprise DBMS, associated applications, and infrastructure do not employ protective measures against unauthorized disclosure and modification during reception, this is a finding.

Redis Enterprise Software (RS) can use industry-standard encryption to protect data in transit between a Redis client and RS. For this purpose, RS uses transport layer security (TLS) protocol.

Run the following commands and verify certificates are present:
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
  desc 'fix', %q(To encrypt the connection to the database endpoint with TLS, enter the contents the client certificate to the TLS field.

If configured, Redis Enterprise Software (RS) can use industry-standard encryption to protect the data in transit between a Redis client and RS. For this purpose, RS uses transport layer security (TLS) protocol, which is the more secure successor to SSL.

To enable TLS, the RS cluster nodes, the database, and client must be configured as detailed below.

Configuration of the RS nodes:
By default, each cluster node has a different set of self-signed certificates. These certificates can be replaced with another certificate, preferably a certificate issued by an intermediate certificate authority (CA).

Configuration of the database:
To encrypt the connection to the database endpoint with TLS, enter the contents the client certificate to the TLS field.
Note: Once TLS encryption is enabled for the database endpoint, the database does not accept unsecured connections. TLS encryption can significantly impact database throughput and latency.

Adding TLS CA signed certificates to the proxy:
The proxy is responsible for terminating the TLS connection.
Server certificate and key are located on /etc/opt/redislabs:proxy_cert.pem - server certificate thatproxy_key.pem - server certificate key*any update on these requires a proxy restart

Enabling of TLS is done via the "ssl authentication" field in the UI. It is a requirement to add a client-side certificate as a TLS connection via client certificate authentication (not just server-side authentication).

Installing CA signed certificates:
Replace the RS server certificates and key on all nodes with the CA signed certificate and restart the proxy.
Note: A certificate for the databases' endpoint should be assigned for the same domain as the cluster name. For example, for a cluster with the name "redislabs.com" the certificate should be for "*.redislabs.com".

Add the TLS client certificates in the UI including CA certificates and any intermediate certificates by chaining the certificate into one file (use a cat command to chain the certificates).
On the client side make sure to import and trust the CA and intermediate certificates (chain the CA certificate with intermediate as one file to use and import).

Client configuration:
To connect to a database configured with TLS encryption, either use one of the Redis clients that inherently support SSL encryption, or use any Redis client and create a secured tunnel between the client machine and the RS nodes.

To create a secure tunnel between the client machine and the RS nodes, use tools that enable this functionality, such as spiped or stunnel. An example of how to use stunnel is detailed below.
Note: For security reasons, RS supports only the TLS protocol. Therefore, make sure that the Redis client or secured tunnel solution used supports TLS, preferably TLS v1.2.

When using self-signed certificates on the cluster nodes, make sure to copy these certificates to the client machines as well, thereby enabling the client to validate the cluster nodes.

When using a certificate issued by an intermediate certificate authority (CA) on the cluster nodes, make sure that the CA root certificate is installed on the client machines.

Example of how to secure client connection with TLS using stunnel: 
The instructions below explain how to use stunnel for setting up a secure tunnel between a client machine and the RS nodes when the client is running on Ubuntu, using the default RS nodes' self-signed certificates, and a self-signed certificate on the client machine.

1. Install stunnel version 5 or higher on the client machine. Older versions of stunnel do not support the TLS protocol.

2. Create a self-signed certificate on the client machine:

3. Generate a private key by running the following commands:
sudo su
openssl genrsa -out /etc/stunnel/keyclient.pem 4096

4. Generate a client certificate by running the following commands:
openssl req -new -x509 -key /etc/stunnel/keyclient.pem
-out
/etc/stunnel/cert.pem -days 1826

5. When prompted, enter the appropriate configuration details for the certificate.

6. Copy the RS node certificates from all nodes to the client machine. The certificates are saved in a file named proxy_cert.pem, which is stored in /etc/opt/redislabs in each node.

7. Rename the certificate files fetched from the RS nodes as certsvr.pem. For example: certsvr1.pem, certsvr2.pem.

8. Create a single file for all of the server certificates on the client machine by running the following command from the OS CLI. For example: cat /etc/stunnel/certsvr1.pem /etc/stunnel/certsvr2.pem > /etc/stunnel/servercerts.pem

9. Configure stunnel for the connection to RS by using the steps below:

10. Create a redislabs.conf file in /etc/stunnel folder.

11. Make sure that the certificates that have been generated exist in the following folder: /etc/stunnel.

12. Edit the redislabs.conf content to look as follows:cert = /etc/stunnel/cert.pem key = /etc/stunnel/keyclient.pem cafile = /etc/stunnel/servercerts.pem verify = 2 delay = yes output = /tmp/stunnel.log pid = /tmp/stunnel.pid[redislabs] client = yes accept = [server IP address]:[configured port] connect = [database endpoint value] Where [database endpoint value] is the database endpoint as can be retrieved from RS.

Note: The value for the accept parameter is the local IP and port that is used for redirecting the traffic through the secure tunnel to the database endpoint configured in the connect parameter.

13. Copy the contents of the client certificate from cert.pem and enter them in the SSL Client Authentication field, in the RS UI, of the database to be secured. When done, be sure to save the change.

14. Start the stunnel service by running the following command: service stunnel restart

Note: Any change made to the stunnel configuration requires restarting the stunnel service.

15. Check the stunnel log file to verify that the connection is working properly. The log file is created under the root folder within the configuration mentioned above.

16. Test the connection to the Redis database from the client machine. Use redis-cli to run commands on the client machine, and the commands are redirected from the local machine's port [configured port] to the RS database endpoint. Note that the connection to the Redis database is done through the local port; do not try to connect directly to the database endpoint.

TLS version information:
To set the minimum TLS version that can be used for encrypting the data in transit between a Redis client and a Redis Enterprise cluster, use the REST API or the following rladmin command:
rladmin> cluster config min_data_TLS_version [version, e.g., 1.2]

Note that if a client supports an older TLS version, the communication is not be allowed.)
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54684r863376_chk'
  tag severity: 'medium'
  tag gid: 'V-251249'
  tag rid: 'SV-251249r863377_rule'
  tag stig_id: 'RD6X-00-011700'
  tag gtitle: 'SRG-APP-000442-DB-000379'
  tag fix_id: 'F-54638r804936_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
