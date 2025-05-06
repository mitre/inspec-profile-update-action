control 'SV-237780' do
  title 'The network device must be configured to use DoD approved OCSP responders or CRLs to validate certificates used for PKI-based authentication.'
  desc 'Once issued by a DoD certificate authority (CA), public key infrastructure (PKI) certificates are typically valid for 3 years or shorter within the DoD. However, there are many reasons a certificate may become invalid before the prescribed expiration date. For example, an employee may leave or be terminated and still possess the smartcard on which the PKI certificates were stored. Another example is that a smartcard containing PKI certificates may become lost or stolen. A more serious issue could be that the CA or server which issued the PKI certificates has become compromised, thereby jeopardizing every certificate keypair that was issued by the CA. These examples of revocation use cases and many more can be researched further using Internet cybersecurity resources.

PKI user certificates presented as part of the identification and authentication criteria (e.g., DoD PKI as multi-factor authentication [MFA]) must be checked for validity by network devices. For example, valid PKI certificates are digitally signed by a trusted DoD certificate authority (CA). Additionally, valid PKI certificates are not expired, and valid certificates have not been revoked by a DoD CA.

Network devices can verify the validity of PKI certificates by checking with an authoritative CA. One method of checking the status of PKI certificates is to query databases referred to as certificate revocation lists (CRL). These are lists which are published, updated, and maintained by authoritative DoD CAs. For example, once certificates are expired or revoked, issuing CAs place the certificates on a certificate revocation list (CRL). Organizations can download these lists periodically (i.e. daily or weekly) and store them locally on the devices themselves or even onto another nearby local enclave resource. Storing them locally ensures revocation status can be checked even if Internet connectivity is severed at the enclave’s point of presence (PoP). However, CRLs can be rather large in storage size and further, the use of CRLs can be rather taxing on some computing resources.

Another method of validating certificate status is to use the online certificate status protocol (OCSP). Using OCSP, a requestor (i.e. the network device which the user is trying to authenticate to) sends a request to an authoritative CA challenging the validity of a certificate that has been presented for identification and authentication. The CA receives the request and sends a digitally signed response indicating the status of the user’s certificate as valid, revoked, or unknown. Network devices should only allow access for responses that indicate the certificates presented by the user were considered valid by an approved DoD CA. OCSP is the preferred method because it is fast, provides the most current status, and is lightweight.'
  desc 'check', 'Verify the network device is configured to validate certificates used for PKI-based authentication using DoD approved OCSP or CRL resources. If the network device is not configured to validate certificates used for PKI-based authentication using DoD approved OCSP or CRL sources, this is a finding.

Note: This requirement may be not applicable if the network device is not configured to use DoD PKI as multi-factor authentication for interactive logins. In that scenario, this requirement should be included as part of the business case and discussion with the AO who is required to accept the risk of the alternative solution. However, if alternative DoD or AO approved solutions are employed which still rely on some form of PKI (digital certificates), this requirement should be tailored to configure certificate validation of the accepted solution. An example may be the reinforcement of a list of explicitly allowed, unique per user, session certificates that are both configured on the devices and documented with the ISSO and ISSM (implying that all other certificates are also explicitly forbidden).'
  desc 'fix', 'Configure the network device to validate certificates used for PKI-based authentication using DoD approved OCSP or CRL sources.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-40990r663937_chk'
  tag severity: 'high'
  tag gid: 'V-237780'
  tag rid: 'SV-237780r879612_rule'
  tag stig_id: 'SRG-APP-000175-NDM-000262'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-40949r663938_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
