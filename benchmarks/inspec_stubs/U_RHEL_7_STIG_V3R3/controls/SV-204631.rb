control 'SV-204631' do
  title 'The Red Hat Enterprise Linux operating system must have the required packages for multifactor authentication installed.'
  desc 'Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).

'
  desc 'check', 'Verify the operating system has the packages required for multifactor authentication installed.

Check for the presence of the packages required to support multifactor authentication with the following commands:

# yum list installed pam_pkcs11
pam_pkcs11-0.6.2-14.el7.noarch.rpm

If the "pam_pkcs11" package is not installed, this is a finding.'
  desc 'fix', 'Configure the operating system to implement multifactor authentication by installing the required packages.

Install the pam_pkcs11 package with the following command:

# yum install pam_pkcs11'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4755r462472_chk'
  tag severity: 'medium'
  tag gid: 'V-204631'
  tag rid: 'SV-204631r603261_rule'
  tag stig_id: 'RHEL-07-041001'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-4755r462473_fix'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000375-GPOS-00161', 'SRG-OS-000375-GPOS-00162']
  tag 'documentable'
  tag legacy: ['SV-87041', 'V-72417']
  tag cci: ['CCI-001953', 'CCI-001954', 'CCI-001948']
  tag nist: ['IA-2 (12)', 'IA-2 (12)', 'IA-2 (11)']
end
