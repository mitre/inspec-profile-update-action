control 'SV-258595' do
  title 'The ICS must be configured to use an approved Commercial Solution for Classified (CSfC) when transporting classified traffic across an unclassified network.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data.

The National Security Agency/Central Security Service's (NSA/CSS) CSfC Program enables commercial products to be used in layered solutions to protect classified National Security Systems (NSS) data. Currently, Suite B cryptographic algorithms are specified by NIST and are used by NSA's Information Assurance Directorate in solutions approved for protecting classified and unclassified NSS. However, quantum resistant algorithms will be required for future required Suite B implementations.

"
  desc 'check', 'If the ICS VPN Gateway is not being used to carry classified data (e.g., Secret, Top Secret, etc.), this is Not Applicable.

1. Navigate to System >> Configuration >> Inbound SSL Options. Verify that under "Allowed Encryption Strength", if "SuiteB - Accept only SuiteB ciphers" is checked.
2. Navigate to System >> Configuration >> Certificates >> Device Certificates. Verify the certificate being used by the ICS is an ECC P-384 Public Key.

If the ICS is not configured to use only SuiteB ciphers with ECC P-384 keys for transporting classified traffic, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to System >> Configuration >> Certificates >> Device Certificates.
1. Click "New CSR".
2. Add a Common Name in FQDN format.
3. Add a Country code of "US".
4. Under key type, select "ECC".
5. Under the key length, select "P-384".
6. Click "Create CSR".
7. Copy the Base 64/PEM encoded certificate request that is shown on the screen and paste it to a text file. Ensure the file has the file suffix of .csr.
8. Go through the local RA process for DOD Web Server certificate requests. Ensure that SANs are added to the certificate by the issuing CA to include the hostname, cluster names, and all FQDNs.
9. Once the certificate is provided by the CA, go to System >> Configuration >> Certificates >> Device Certificates.
10. Click "Browse" and select the certificate file issued by the CA. Then click "Import".
11. Click "Save Changes".
12. Click on the imported certificate.
13. On the "Internal Port", click "add" for the cluster internal VIP and <Internal Port>.
14. On the "External Port" click "add" for the cluster external VIP and <External Port>.
15. Check the box for "Management Port".
16. Under "Certificate Status Checking", click the box for "Use CRLs".
17. Click "Save Changes".

In the ICS Web UI, navigate to System >> Configuration >> Inbound SSL Options.
1. Under "Allowed Encryption Strength", click "SuiteB - Accept only SuiteB ciphers".
2. Click "Save Changes" and accept the cipher suite changes.'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62335r930471_chk'
  tag severity: 'medium'
  tag gid: 'V-258595'
  tag rid: 'SV-258595r930473_rule'
  tag stig_id: 'IVCS-VN-000350'
  tag gtitle: 'SRG-NET-000352-VPN-001460'
  tag fix_id: 'F-62244r930472_fix'
  tag satisfies: ['SRG-NET-000352-VPN-001460', 'SRG-NET-000565-VPN-002400', 'SRG-NET-000565-VPN-002390']
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
