control 'SV-36176' do
  title 'The Kerberos service ticket maximum lifetime must be limited to 600 minutes or less.'
  desc 'This setting determines the maximum amount of time (in minutes) that a granted session ticket can be used to access a particular service.  Session tickets are used only to authenticate new connections with servers.  Ongoing operations are not interrupted if the session ticket used to authenticate the connection expires during the connection.'
  desc 'check', 'Verify the following is configured in the Default Domain Policy.

Open "Group Policy Management".
Navigate to "Group Policy Objects" in the Domain being reviewed (Forest >> Domains >> Domain). 
Right click on the "Default Domain Policy", select "Edit".
Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the value for "Maximum lifetime for service ticket" is "0" or greater than "600" minutes, this is a finding.'
  desc 'fix', %q(Configure the policy value in the Default Domain Policy for Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy >> "Maximum lifetime for service ticket" to a maximum of "600" minutes, but not "0" which equates to "Ticket doesn't expire".)
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-71081r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2377'
  tag rid: 'SV-36176r2_rule'
  tag stig_id: 'AD.4030_2008_R2'
  tag gtitle: 'Kerberos-Service Ticket Lifetime'
  tag fix_id: 'F-76925r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
