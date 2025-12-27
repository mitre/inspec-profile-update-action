control 'SV-248545' do
  title 'OL 8 must prevent system daemons from using Kerberos for authentication.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised.

OL 8 systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

The key derivation function (KDF) in Kerberos is not FIPS compatible. Ensuring the system does not have any keytab files present prevents system daemons from using Kerberos for authentication. A keytab is a file containing pairs of Kerberos principals and encrypted keys.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.'
  desc 'check', 'Verify that OL 8 prevents system daemons from using Kerberos for authentication.

If the system is a server using krb5-server-1.17-18.el8.x86_64 or newer, this requirement is not applicable.

If the system is a workstation using krb5-workstation-1.17-18.el8.x86_64 or newer, this requirement is not applicable.

Check if there are available keytabs with the following command:

$ sudo ls -al /etc/*.keytab

If this command produces any file(s), this is a finding.'
  desc 'fix', 'Configure OL 8 to prevent system daemons from using Kerberos for authentication.

Remove any files with the .keytab extension from the operating system.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51979r779199_chk'
  tag severity: 'medium'
  tag gid: 'V-248545'
  tag rid: 'SV-248545r779201_rule'
  tag stig_id: 'OL08-00-010161'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-51933r779200_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
