control 'SV-258620' do
  title 'The ICS must be configured to use DOD approved OCSP responders or CRLs to validate certificates used for PKI-based authentication.'
  desc "Once issued by a DOD certificate authority (CA), public key infrastructure (PKI) certificates are typically valid for three years or shorter within the DOD. However, there are many reasons a certificate may become invalid before the prescribed expiration date. For example, an employee may leave or be terminated and still possess the smartcard on which the PKI certificates were stored. Another example is that a smartcard containing PKI certificates may become lost or stolen. A more serious issue could be that the CA or server which issued the PKI certificates has become compromised, thereby jeopardizing every certificate keypair that was issued by the CA. These examples of revocation use cases and many more can be researched further using internet cybersecurity resources.

PKI user certificates presented as part of the identification and authentication criteria (e.g., DOD PKI as multifactor authentication [MFA]) must be checked for validity by network devices. For example, valid PKI certificates are digitally signed by a trusted DOD certificate authority (CA). Additionally, valid PKI certificates are not expired, and valid certificates have not been revoked by a DOD CA.

Network devices can verify the validity of PKI certificates by checking with an authoritative CA. One method of checking the status of PKI certificates is to query databases referred to as certificate revocation lists (CRL). These are lists which are published, updated, and maintained by authoritative DOD CAs. For example, once certificates are expired or revoked, issuing CAs place the certificates on a certificate revocation list (CRL). Organizations can download these lists periodically (i.e. daily or weekly) and store them locally on the devices themselves or even onto another nearby local enclave resource. Storing them locally ensures revocation status can be checked even if internet connectivity is severed at the enclave's point of presence (PoP). However, CRLs can be rather large in storage size and further, the use of CRLs can be rather taxing on some computing resources.

Another method of validating certificate status is to use the online certificate status protocol (OCSP). Using OCSP, a requestor (i.e. the network device which the user is trying to authenticate to) sends a request to an authoritative CA challenging the validity of a certificate that has been presented for identification and authentication. The CA receives the request and sends a digitally signed response indicating the status of the user's certificate as valid, revoked, or unknown. Network devices should only allow access for responses that indicate the certificates presented by the user were considered valid by an approved DOD CA. OCSP is the preferred method because it is fast, provides the most current status, and is lightweight."
  desc 'check', 'In the ICS Web UI, navigate to System >> Configuration >> Certificates >> Trusted Client CAs.
1. Click the first DOD client CA.
2. Verify the item "Use OCSP with CRL fallback" is selected under the "Client certificate status checking" setting.
3. Check each other client certificate CA. Verify the setting "Use OCSP with CRL fallback" is selected.

If the ICS is not configured to use DOD approved OCSP responders or CRLs to validate certificates used for PKI-based authentication, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to System >> Configuration >> Certificates >> Trusted Client CAs.
1. Click the first DOD client CA.
2. Set the item to "Use OCSP with CRL fallback" under "Client certificate status checking".
3. Repeat these steps for every other client certificate CA.'
  impact 0.7
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62360r930546_chk'
  tag severity: 'high'
  tag gid: 'V-258620'
  tag rid: 'SV-258620r930548_rule'
  tag stig_id: 'IVCS-NM-000500'
  tag gtitle: 'SRG-APP-000175-NDM-000262'
  tag fix_id: 'F-62269r930547_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
