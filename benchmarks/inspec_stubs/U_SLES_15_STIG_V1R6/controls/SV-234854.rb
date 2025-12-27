control 'SV-234854' do
  title 'The SUSE operating system must have the packages required for multifactor authentication to be installed.'
  desc 'Using an authentication device, such as a Common Access Card (CAC) or token separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification (PIV) card and the DoD CAC.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).

'
  desc 'check', 'Verify the SUSE operating system has the packages required for multifactor authentication installed.

Check for the presence of the packages required to support multifactor authentication with the following commands:

> zypper info pam_pkcs11 | grep -i installed

> zypper info mozilla-nss | grep -i installed

> zypper info mozilla-nss-tools | grep -i installed

> zypper info pcsc-ccid | grep -i installed

> zypper info pcsc-lite | grep -i installed

> zypper info pcsc-tools | grep -i installed

> zypper info opensc | grep -i installed

> zypper info coolkey | grep -i installed

If any of the packages required for multifactor authentication are not installed, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to implement multifactor authentication by installing the required packages.

Install the packages required to support multifactor authentication with the following commands:

> zypper install pam_pkcs11

> zypper install mozilla-nss

> zypper install mozilla-nss-tools

> zypper install pcsc-ccid

> zypper install pcsc-lite

> zypper install pcsc-tools

> zypper install opensc

> zypper install coolkey

Additional information on the configuration of multifactor authentication on the SUSE operating system can be found at https://www.suse.com/communities/blog/configuring-smart-card-authentication-suse-linux-enterprise/.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38042r618831_chk'
  tag severity: 'medium'
  tag gid: 'V-234854'
  tag rid: 'SV-234854r622137_rule'
  tag stig_id: 'SLES-15-010460'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-38005r618832_fix'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000376-GPOS-00161', 'SRG-OS-000377-GPOS-00162']
  tag 'documentable'
  tag cci: ['CCI-001948', 'CCI-001953', 'CCI-001954']
  tag nist: ['IA-2 (11)', 'IA-2 (12)', 'IA-2 (12)']
end
