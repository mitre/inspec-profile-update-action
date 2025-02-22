control 'SV-234817' do
  title 'The SUSE operating system, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.

'
  desc 'check', 'Verify the SUSE operating system for PKI-based authentication had valid certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Check that the certification path to an accepted trust anchor for multifactor authentication is implemented with the following command:

> grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf

cert_policy = ca,oscp_on,signature,crl_auto;

If "cert_policy" is not set to include "ca", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system for PKI-based authentication to validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Modify all of the cert_policy lines in "/etc/pam_pkcs11/pam_pkcs11.conf" to include "ca":

cert_policy = ca,signature,oscp_on;

Note: Additional certificate validation polices are permitted.

Additional information on the configuration of multifactor authentication on the SUSE operating system can be found at https://www.suse.com/communities/blog/configuring-smart-card-authentication-suse-linux-enterprise/.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38005r618720_chk'
  tag severity: 'medium'
  tag gid: 'V-234817'
  tag rid: 'SV-234817r854185_rule'
  tag stig_id: 'SLES-15-010170'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-37968r618721_fix'
  tag satisfies: ['SRG-OS-000066-GPOS-00034', 'SRG-OS-000384-GPOS-00167']
  tag 'documentable'
  tag cci: ['CCI-000185', 'CCI-001991']
  tag nist: ['IA-5 (2) (b) (1)', 'IA-5 (2) (d)']
end
