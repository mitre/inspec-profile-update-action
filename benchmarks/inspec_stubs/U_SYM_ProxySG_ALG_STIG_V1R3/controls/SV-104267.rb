control 'SV-104267' do
  title 'If reverse proxy is used for validating and restricting certs from external entities, and this function is required by the SSP, Symantec ProxySG providing user authentication intermediary services using PKI-based user authentication must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of protected sessions.'
  desc 'Non-DoD-approved PKIs have not been evaluated to ensure they have security controls and identity vetting procedures in place that are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.

The authoritative list of DoD-approved PKIs is published at http://iase.disa.mil/pki-pke/interoperability. DoD-approved PKI CAs may include Category I, II, and III certificates. Category I DoD-Approved External PKIs are PIV issuers. Category II DoD-Approved External PKIs are Non-Federal Agency PKIs cross-certified with the Federal Bridge Certification Authority (FBCA). Category III DoD-Approved External PKIs are Foreign, Allied, or Coalition Partner PKIs.

Deploying the ALG with TLS enabled will require the installation of DoD and/or DoD-Approved CA certificates in the trusted root certificate store of each proxy to be used for TLS traffic. 

This requirement focuses on communications protection for the application session rather than for the network packet.'
  desc 'check', 'Verify that only DoD-approved Certificate Authorities are trusted by the ProxySG for reverse proxy services.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Services >> Proxy Services.
3. Select each HTTPS Reverse Proxy service and click "Edit Service".
4. Note the name of the CCL listed.
5. Browse to SSL >> CA Certificates >> CA Certificate Lists.
6. Select the CCL from step 4 and click "View".
7. Verify that only DoD-approved CA Certifications are listed in the box on the right.

If any CA certifications that are not DoD approved are found in a CCL assigned to a reverse proxy service, this is a finding.'
  desc 'fix', 'Configure reverse proxy services to only trust DoD-approved Certificate Authorities.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Services >> Proxy Services.
3. Browse to SSL >> CA Certificates >> CA Certificate Lists.
4. Click "Import," provide a "Name," and paste in the first DoD CA certificate in PEM format and click "OK". Repeat for each DoD CA certificate desired.
5. Click CA Certificate Lists >> New.
6. Provide a "Name," click each DoD CA certificate created in step 4, and click "Add". Once all certificates have been added, click "OK".
7. Browse to Configuration >> Services >> Proxy Services.
8. Select each HTTPS Reverse Proxy service and click "Edit Service".
9. Select the CCL created in step 6, click "OK," and then click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93499r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94313'
  tag rid: 'SV-104267r1_rule'
  tag stig_id: 'SYMP-AG-000500'
  tag gtitle: 'SRG-NET-000355-ALG-000117'
  tag fix_id: 'F-100429r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
