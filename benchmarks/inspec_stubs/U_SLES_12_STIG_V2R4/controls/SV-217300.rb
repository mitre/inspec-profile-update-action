control 'SV-217300' do
  title 'The SUSE operating system must implement certificate status checking for multifactor authentication.'
  desc 'Using an authentication device, such as a Common Access Card (CAC) or token separate from the information system, ensures credentials stored on the authentication device will not be affected if the information system is compromised.

Multifactor solutions that require devices separate from information systems to gain access include: hardware tokens providing time-based or challenge-response authenticators, and smart cards such as the U.S. Government Personal Identity Verification (PIV) card and the DoD CAC.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

This requirement only applies to components with device-specific functions, or for organizational users (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).

'
  desc 'check', %q(Verify the SUSE operating system implements certificate status checking for multifactor authentication.

Check that certificate status checking for multifactor authentication is implemented with the following command:

# grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module coolkey {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy

cert_policy = ca,ocsp_on,signature,crl_auto;

If "cert_policy" is not set to include "ocsp_on", this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to certificate status checking for PKI authentication.

Modify all of the cert_policy lines in "/etc/pam_pkcs11/pam_pkcs11.conf" to include "ocsp_on".

Note: OCSP allows sending request for certificate status information. Additional certificate validation polices are permitted.

Additional information on the configuration of multifactor authentication on the SUSE operating system can be found at https://www.suse.com/communities/blog/configuring-smart-card-authentication-suse-linux-enterprise/'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18528r370056_chk'
  tag severity: 'medium'
  tag gid: 'V-217300'
  tag rid: 'SV-217300r603262_rule'
  tag stig_id: 'SLES-12-030510'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-18526r370057_fix'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000376-GPOS-00161', 'SRG-OS-000377-GPOS-00162']
  tag 'documentable'
  tag legacy: ['V-77509', 'SV-92205']
  tag cci: ['CCI-001948', 'CCI-001953', 'CCI-001954']
  tag nist: ['IA-2 (11)', 'IA-2 (12)', 'IA-2 (12)']
end
