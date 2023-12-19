control 'SV-217424' do
  title 'The F5 BIG-IP must ensure SSH is disabled for root user logon to prevent remote access using the root account.'
  desc 'The F5 BIG-IP shell must be locked down to limit the ability to modify the configuration through the shell. Preventing attackers from remotely accessing management functions using root account mitigates the risk that unauthorized individuals or processes may gain superuser access to information or privileges. Additionally, the audit records for actions taken using the group account will not identify the specific person who took the actions.'
  desc 'check', 'Verify the F5 BIG-IP shell is locked down to limit the ability to modify the configuration through the shell.  
Log in to the Configuration utility as the administrative user.

Navigate to System > Platform.
Under Root Account, verify the Disable login and Disable bash check boxes are checked.

If the value of systemauth.disablerootlogin and db systemauth.disablebash is not set to “true”, then this is a finding.'
  desc 'fix', 'To ensure that the F5 BIG-IP meets the requirements within the STIG, limit the ability to modify the configuration at the command line. SSH into the command line interface and type in the following commands.

(tmos)# modify sys db systemauth.disablerootlogin value true 
(tmos)# modify sys db systemauth.disablebash value true
(tmos)# save sys config'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18649r290826_chk'
  tag severity: 'medium'
  tag gid: 'V-217424'
  tag rid: 'SV-217424r879588_rule'
  tag stig_id: 'F5BI-DM-000284'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-18647r513229_fix'
  tag 'documentable'
  tag legacy: ['SV-106833', 'V-97729']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
