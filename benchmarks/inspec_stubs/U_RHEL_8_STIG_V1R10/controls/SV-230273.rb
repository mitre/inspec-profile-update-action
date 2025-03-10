control 'SV-230273' do
  title 'RHEL 8 must have the packages required for multifactor authentication installed.'
  desc 'Using an authentication device, such as a DoD Common Access Card (CAC) or token that is separate from the information system, ensures that even if the information system is compromised, credentials stored on the authentication device will not be affected.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification (PIV) card and the DoD CAC.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).'
  desc 'check', 'Verify the operating system has the packages required for multifactor authentication installed with the following commands:

$ sudo yum list installed openssl-pkcs11

openssl-pkcs11.x86_64          0.4.8-2.el8          @anaconda

If the "openssl-pkcs11" package is not installed, ask the administrator to indicate what type of multifactor authentication is being utilized and what packages are installed to support it.  If there is no evidence of multifactor authentication being used, this is a finding.'
  desc 'fix', 'Configure the operating system to implement multifactor authentication by installing the required package with the following command:

$ sudo yum install openssl-pkcs11'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32942r743941_chk'
  tag severity: 'medium'
  tag gid: 'V-230273'
  tag rid: 'SV-230273r854028_rule'
  tag stig_id: 'RHEL-08-010390'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-32917r743942_fix'
  tag 'documentable'
  tag cci: ['CCI-001948']
  tag nist: ['IA-2 (11)']
end
