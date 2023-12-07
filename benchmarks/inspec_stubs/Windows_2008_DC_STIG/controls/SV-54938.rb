control 'SV-54938' do
  title 'The Synchronize directory service data user right must be configured to include no accounts or groups (blank).'
  desc 'A Windows account with the "Synchronize directory service data" right has the ability to read all information in the AD database. This bypasses the object access permissions that would otherwise restrict access to the data. The scope of access granted by this right is too broad for secure usage. Specific object permissions or other group membership assignments could be used to provide access on an appropriate scale.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups are granted the "Synchronize directory service data" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Synchronize directory service data" to be defined but containing no entries (blank).'
  impact 0.7
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-48699r2_chk'
  tag severity: 'high'
  tag gid: 'V-12780'
  tag rid: 'SV-54938r1_rule'
  tag stig_id: 'DS00.0210_2008'
  tag gtitle: 'Synchronize Directory Service Data'
  tag fix_id: 'F-47820r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
