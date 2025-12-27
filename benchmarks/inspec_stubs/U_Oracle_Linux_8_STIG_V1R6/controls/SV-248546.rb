control 'SV-248546' do
  title 'The krb5-workstation package must not be installed on OL 8.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised.

OL 8 systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

Currently, Kerberos does not use FIPS 140-2 cryptography.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.'
  desc 'check', 'Verify the krb5-workstation package has not been installed on the system with the following commands:

If the system is a server or is using krb5-workstation-1.17-18.el8.x86_64 or newer, this is Not Applicable.

$ sudo yum list installed krb5-workstation

krb5-workstation.x86_64 1.17-9.el8 repository

If the krb5-workstation package is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Document the krb5-workstation package with the ISSO as an operational requirement or remove it from the system with the following command:

$ sudo yum remove krb5-workstation'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51980r779202_chk'
  tag severity: 'medium'
  tag gid: 'V-248546'
  tag rid: 'SV-248546r779204_rule'
  tag stig_id: 'OL08-00-010162'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-51934r779203_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
