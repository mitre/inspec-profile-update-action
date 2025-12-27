control 'SV-235822' do
  title 'The certificate chain used by Universal Control Plane (UCP) client bundles must match what is defined in the System Security Plan (SSP) in Docker Enterprise.'
  desc "Both the UCP and Docker Trusted Registry (DTR) components of Docker Enterprise leverage the same authentication and authorization backplane known as eNZi. UCP has the ability to use external certificates or internal self-signed. In the case of self-signed UCP includes a certificate authority which is used to sign client bundles and to authenticate users via the eNZi backplane. With an external certificate authority (CA) users will use their existing x509 certs. The external CA will be added in an administrative function and will dictate the root CA for the user's chain."
  desc 'check', 'via CLI: Execute the following command from within the directory in which the UCP client bundle is located.

(Linux) openssl x509 -noout -text -in cert.pem |grep "Subject\\|Issuer"

Verify that the Subject and Issuer output matches that which is defined in the SSP.

If the Subject and Issuer do not match what is documented in the SSP, this is a finding.'
  desc 'fix', %q(via GUI:

As any user with access to UCP, within the UCP web console, click on the username dropdown in the top-left corner, and select "My Profile". On the "Client Bundles" tab, select the "New Client Bundle" dropdown and click "Add Existing Client Bundle". Provide an appropriate "Label", and in the "Public Key" field, paste the public key of the certificate chain provided to that user by the organization. Click "Confirm" to save the bundle.

via CLI:

Linux (requires curl): As a Docker EE Admin, execute the following commands using a client bundle and from a machine with connectivity to the UCP management console.

curl --cacert ca.pem --cert cert.pem --key key.pem -X POST -H "Content-Type: application/json" -d '{"certificates":[{"cert":"[encoded_PEM_for_cert]","label":"[cert_label]"}],"label":"[key_description]","publicKey":"[encoded_PEM_for_public_key]"}' https://[ucp_url]/api/accounts/[account_name_or_id]/publickeys)
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39041r627591_chk'
  tag severity: 'medium'
  tag gid: 'V-235822'
  tag rid: 'SV-235822r627593_rule'
  tag stig_id: 'DKER-EE-002380'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-39004r627592_fix'
  tag 'documentable'
  tag legacy: ['SV-104817', 'V-95679']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
