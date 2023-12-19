control 'SV-208931' do
  title 'If the system is using LDAP for authentication or account information, the system must use a TLS connection using FIPS 140-2 approved cryptographic algorithms.'
  desc 'The ssl directive specifies whether to use ssl or not. If not specified it will default to "no". It should be set to "start_tls" rather than doing LDAP over SSL.'
  desc 'check', 'If the system does not use LDAP for authentication or account information, this is not applicable.

To ensure LDAP is configured to use TLS for all transactions, run the following command: 

$ grep start_tls /etc/pam_ldap.conf

If no lines are returned, this is a finding.'
  desc 'fix', 'Configure LDAP to enforce TLS use. First, edit the file "/etc/pam_ldap.conf", and add or correct the following lines: 

ssl start_tls

Then review the LDAP server and ensure TLS has been configured.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9184r357773_chk'
  tag severity: 'medium'
  tag gid: 'V-208931'
  tag rid: 'SV-208931r603263_rule'
  tag stig_id: 'OL6-00-000252'
  tag gtitle: 'SRG-OS-000250'
  tag fix_id: 'F-9184r357774_fix'
  tag 'documentable'
  tag legacy: ['SV-65023', 'V-50817']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
