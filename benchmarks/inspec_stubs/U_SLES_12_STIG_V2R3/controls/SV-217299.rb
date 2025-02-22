control 'SV-217299' do
  title 'The SUSE operating system must have the packages required for multifactor authentication to be installed.'
  desc 'Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).

'
  desc 'check', 'Verify the SUSE operating system has the packages required for multifactor authentication installed.

Check for the presence of the packages required to support multifactor authentication with the following commands:

# zypper se pam_pkcs11

i | pam_pkcs11 | PKCS #11 PAM Module | package

# zypper se mozilla-nss

i | mozilla-nss | Network Security Services | package
i | mozilla-nss-tools | Tools for developing, debugging, and managing applications t-> | package

# zypper se pcsc

i | pcsc-ccid | PCSC Driver for CCID Based Smart Card Readers and GemPC Twin -> | package
i | pcsc-lite | PCSC Smart Cards Library | package
i | pcsc-tools | PCSC Tools | package

# zypper se opensc

i | opensc | Smart Card Utilities | package

# zypper info coolkey | grep -i installed

Installed: Yes

If any of the packages required for multifactor authentication are not installed, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to implement multifactor authentication by installing the required packages.

Install the packages required to support multifactor authentication with the following commands:

#zypper install pam_pkcs11

#zypper install mozilla-nss

#zypper install mozilla-nss-tools

#zypper install pcsc-ccid

#zypper install pcsc-lite

#zypper install pcsc-tools

#zypper install opensc

#zypper install coolkey

Additional information on the configuration of multifactor authentication on the SUSE operating system can be found at https://www.suse.com/communities/blog/configuring-smart-card-authentication-suse-linux-enterprise/'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18527r370053_chk'
  tag severity: 'medium'
  tag gid: 'V-217299'
  tag rid: 'SV-217299r603262_rule'
  tag stig_id: 'SLES-12-030500'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-18525r370054_fix'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000376-GPOS-00161', 'SRG-OS-000377-GPOS-00162']
  tag 'documentable'
  tag legacy: ['V-77507', 'SV-92203']
  tag cci: ['CCI-001948', 'CCI-001953', 'CCI-001954']
  tag nist: ['IA-2 (11)', 'IA-2 (12)', 'IA-2 (12)']
end
