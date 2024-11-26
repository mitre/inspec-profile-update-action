control 'SV-96045' do
  title 'For locally created accounts in the application, the Central Log Server must be configured to allow the use of a temporary password for system logons with an immediate change to a permanent password.'
  desc 'Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial logon. 

Temporary passwords are typically used to allow access to applications when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts that allow the users to log on, yet force them to change the password once they have successfully authenticated.

The risk can be mitigated by allowing only the account of last resort to be configured locally. This requirement does not apply to that account.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to allow the use of a temporary password for system logons with an immediate change to a permanent password.

If the Central Log Server is not configured to allow the use of a temporary password for system logons with an immediate change to a permanent password, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to allow the use of a temporary password for system logons with an immediate change to a permanent password.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-81035r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81331'
  tag rid: 'SV-96045r1_rule'
  tag stig_id: 'SRG-APP-000397-AU-002590'
  tag gtitle: 'SRG-APP-000397-AU-002590'
  tag fix_id: 'F-88115r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
