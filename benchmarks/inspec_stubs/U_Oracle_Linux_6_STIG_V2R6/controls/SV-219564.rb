control 'SV-219564' do
  title 'The LDAP client must use a TLS connection using trust certificates signed by the site CA.'
  desc 'The tls_cacertdir or tls_cacertfile directives are required when tls_checkpeer is configured (which is the default for openldap versions 2.1 and up). These directives define the path to the trust certificates signed by the site CA.'
  desc 'check', 'If the system does not use LDAP for authentication or account information, this is not applicable.

To ensure TLS is configured with trust certificates, run the following command: 

# grep cert /etc/pam_ldap.conf

If there is no output, or the lines are commented out, this is a finding.'
  desc 'fix', %q(Ensure a copy of the site's CA certificate has been placed in the file "/etc/pki/tls/CA/cacert.pem". Configure LDAP to enforce TLS use and to trust certificates signed by the site's CA. First, edit the file "/etc/pam_ldap.conf", and add or correct either of the following lines: 

tls_cacertdir /etc/pki/tls/CA

or 

tls_cacertfile /etc/pki/tls/CA/cacert.pem

Then review the LDAP server and ensure TLS has been configured.)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21289r358232_chk'
  tag severity: 'medium'
  tag gid: 'V-219564'
  tag rid: 'SV-219564r793821_rule'
  tag stig_id: 'OL6-00-000253'
  tag gtitle: 'SRG-OS-000250'
  tag fix_id: 'F-21288r358233_fix'
  tag 'documentable'
  tag legacy: ['SV-65025', 'V-50819']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
