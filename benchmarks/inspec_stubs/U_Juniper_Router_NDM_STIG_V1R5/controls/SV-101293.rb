control 'SV-101293' do
  title 'The Juniper router must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement. The configuration below is an example of a Certificate Authority profile defining name of the CA, the location of CRL for revocation check and to refresh the CRL every 24 hours, and the email address to send a certificate request.

security {
    pki {
        ca-profile DODXX_CA {
            ca-identity xxxxx.mil;
            revocation-check {
                crl {
                    url http://server1.xxxxx.mil/CertEnroll/example.crl;
                    refresh-interval 24;
                }
            }
            administrator {
                email-address "certadmin@xxxxx.mil";
            }
        }
    }
}

If the router is not configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider, this is a finding.'
  desc 'fix', 'Step 1. Create a trusted profile and email address to send certificate request to.

[edit security]
set pki ca-profile DODXX_CA ca-identity xxxxx.mil
set pki ca-profile DODXX_CA administrator email-address certadmin@xxxxx.mil

Step 2. Create a revocation check to specify a method for checking certificate revocation.

set pki ca-profile DODXX_CA revocation-check crl url http://server1.example.mil/CertEnroll/example.crl
set pki ca-profile DODXX_CA revocation-check crl refresh-interval 24'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-90347r3_chk'
  tag severity: 'medium'
  tag gid: 'V-91193'
  tag rid: 'SV-101293r1_rule'
  tag stig_id: 'JUNI-ND-001430'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-97391r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
