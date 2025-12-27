control 'SV-226066' do
  title 'The Kerberos service ticket maximum lifetime must be limited to 600 minutes or less.'
  desc 'This setting determines the maximum amount of time (in minutes) that a granted session ticket can be used to access a particular service.  Session tickets are used only to authenticate new connections with servers.  Ongoing operations are not interrupted if the session ticket used to authenticate the connection expires during the connection.'
  desc 'check', 'Verify the following is configured in the Default Domain Policy.

Open "Group Policy Management".
Navigate to "Group Policy Objects" in the Domain being reviewed (Forest > Domains > Domain). 
Right click on the "Default Domain Policy".
Select Edit.
Navigate to Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Kerberos Policy.

If the value for "Maximum lifetime for service ticket" is 0 or greater than 600 minutes, this is a finding.'
  desc 'fix', %q(Configure the policy value in the Default Domain Policy for Computer Configuration ->  Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy -> "Maximum lifetime for service ticket" to a maximum of 600 minutes, but not 0, which equates to "Ticket doesn't expire".)
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27768r475521_chk'
  tag severity: 'medium'
  tag gid: 'V-226066'
  tag rid: 'SV-226066r794792_rule'
  tag stig_id: 'WN12-AC-000011-DC'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27756r794791_fix'
  tag 'documentable'
  tag legacy: ['SV-51162', 'V-2377']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
