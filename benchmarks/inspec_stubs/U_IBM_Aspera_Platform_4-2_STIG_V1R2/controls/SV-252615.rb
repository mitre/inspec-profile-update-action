control 'SV-252615' do
  title 'The IBM Aspera High-Speed Transfer Endpoint must be configured to protect the authenticity of communications sessions.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

This requirement focuses on communications protection for the application session rather than for the network packet and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of mutual authentication (two-way/bidirectional).'
  desc 'check', 'For implementations using IBM Aspera High-Speed Transfer Endpoint, check for a <ssh_host_key_fingerprint> entry within the <server> section within The IBM Aspera High-Speed Transfer Endpoint installation configuration file at /opt/aspera/etc/aspera.conf using the following command:

$ sudo more /opt/aspera/etc/aspera.conf | grep ssh_host_key_fingerprint

If the command does not return XML containing the fingerprint, this is a finding.

Test that the certificates used by Aspera Node service is a valid signed certificate (not self signed) by running the following command after substituting the FQDN for "servername":

$ sudo /opt/aspera/bin/openssl s_client -connect servername:9092

If the certificate is not DoD issued, this is a finding.'
  desc 'fix', %q(For implementations using the IBM Aspera High Speed Transfer Endpoint, configure the host key fingerprint using the following procedure:

1. Retrieve the server's SHA-1 fingerprint using the following command:

$ sudo cat /etc/ssh/ssh_host_rsa_key.pub | awk '{print $2}' | base64 -d | sha1sum

2. Set the SSH host key fingerprint in /opt/aspera/etc/aspera.conf using the following command after substituting the string returned from the previous command for "INSERTFINGERPRINTHERE":

$ sudo /opt/aspera/bin/asconfigurator -x "set_server_data;ssh_host_key_fingerprint,INSERTFINGERPRINTHERE"

3. Restart the IBM Aspera Node service to activate the change using the following command:

$ sudo systemctl restart asperanoded.service

Implement a signed certificate (/opt/aspera/etc/aspera_server_cert.pem) for the IBM Aspera High Speed Transfer Endpoint according to the instructions "Setting up SSL for your Nodes" and "Installing SSL Certificates" within the IBM Aspera High-Speed Transfer Server Admin Guide.

Restart the IBM Aspera Node service to activate the change to the certificate using the following command:

$ sudo systemctl restart asperanoded.service)
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56071r818013_chk'
  tag severity: 'medium'
  tag gid: 'V-252615'
  tag rid: 'SV-252615r818015_rule'
  tag stig_id: 'ASP4-TE-030120'
  tag gtitle: 'SRG-NET-000230-ALG-000113'
  tag fix_id: 'F-56021r818014_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
