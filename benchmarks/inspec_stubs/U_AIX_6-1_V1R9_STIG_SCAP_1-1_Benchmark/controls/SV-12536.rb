control 'SV-12536' do
  title 'The SYSTEM attribute must not be set to NONE for any account.'
  desc "The SYSTEM attribute in /etc/security/user defines the mechanisms used to authenticate specific user accounts.  If the value is set to NONE, other attributes will be used to determine the authentication mechanisms, but if these attributes are not present, no authentication will be performed.  To ensure authentication is always used for the system's accounts, the SYSTEM attribute must always be set to a valid setting other than NONE."
  desc 'fix', 'Edit /etc/security/user and change any SYSTEM=NONE settings to a valid authentication setting.'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag severity: 'high'
  tag gid: 'V-12035'
  tag rid: 'SV-12536r2_rule'
  tag stig_id: 'GEN000000-AIX00080'
  tag gtitle: 'GEN000000-AIX00080'
  tag fix_id: 'F-11292r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000225', 'CCI-000764']
  tag nist: ['AC-6', 'IA-2']
end
