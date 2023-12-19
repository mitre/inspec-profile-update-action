control 'SV-78445' do
  title 'The system must use Active Directory authentication.'
  desc 'The application must ensure users are authenticated with an individual authenticator prior to using a group authenticator.  Using Active Directory for authentication provides more robust account management capabilities.'
  desc 'check', 'Verify the Windows server hosting vCenter is joined to the domain and access to the server and to vCenter is done using Active Directory accounts.

If the vCenter server is not joined to an Active Directory domain, this is a finding.

If Active Directory based accounts are not used for daily operations of the vCenter server, this is a finding.

If Active Directory is not used in the environment, this is not applicable.'
  desc 'fix', 'If the server hosting vCenter is not joined to the domain follow the OS specific procedures to join it to Active Directory.

If local accounts are used for normal operations then Active Directory accounts should be created and used.'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64705r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63955'
  tag rid: 'SV-78445r1_rule'
  tag stig_id: 'VCWN-06-000009'
  tag gtitle: 'SRG-APP-000153'
  tag fix_id: 'F-69883r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
