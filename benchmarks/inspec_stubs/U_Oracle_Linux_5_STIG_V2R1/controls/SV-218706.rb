control 'SV-218706' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS certificate file must have mode 0644 or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Identify the LDAP TLS Certificate file:

# cat <ldap_config_file> | grep -i "^tls"

TLSCACertificatePath <path>
TLSCACertificateFile <filename>
TLSCertificateFile <filename>

For each TLSCACertificateFile and TLSCertificateFile defined in the configuration file, verify the file permissions:

# ls -la <tls_certificate_file>

If the mode of the file is more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the file.
# chmod 0644 <certpath>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20181r556535_chk'
  tag severity: 'medium'
  tag gid: 'V-218706'
  tag rid: 'SV-218706r603259_rule'
  tag stig_id: 'GEN008260'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20179r556536_fix'
  tag 'documentable'
  tag legacy: ['V-22569', 'SV-63249']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
