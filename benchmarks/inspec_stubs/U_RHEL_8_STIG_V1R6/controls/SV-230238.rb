control 'SV-230238' do
  title 'RHEL 8 must prevent system daemons from using Kerberos for authentication.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

RHEL 8 systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

The key derivation function (KDF) in Kerberos is not FIPS compatible.  Ensuring the system does not have any keytab files present prevents system daemons from using Kerberos for authentication.  A keytab is a file containing pairs of Kerberos principals and encrypted keys.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.'
  desc 'check', 'Verify that RHEL 8 prevents system daemons from using Kerberos for authentication.

If the system is a server utilizing krb5-server-1.17-18.el8.x86_64 or newer, this requirement is not applicable.
If the system is a workstation utilizing krb5-workstation-1.17-18.el8.x86_64 or newer, this requirement is not applicable.

Check if there are available keytabs with the following command:

$ sudo ls -al /etc/*.keytab

If this command produces any file(s), this is a finding.'
  desc 'fix', 'Configure RHEL 8 to prevent system daemons from using Kerberos for authentication.

Remove any files with the .keytab extension from the operating system.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32907r646861_chk'
  tag severity: 'medium'
  tag gid: 'V-230238'
  tag rid: 'SV-230238r646862_rule'
  tag stig_id: 'RHEL-08-010161'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-32882r567461_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
