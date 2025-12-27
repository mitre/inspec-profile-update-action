control 'SV-226065' do
  title 'Kerberos user logon restrictions must be enforced.'
  desc 'This policy setting determines whether the Kerberos Key Distribution Center (KDC) validates every request for a session ticket against the user rights policy of the target computer.  The policy is enabled by default which is the most secure setting for validating access to target resources is not circumvented.'
  desc 'check', 'Verify the following is configured in the Default Domain Policy.

Open "Group Policy Management".
Navigate to "Group Policy Objects" in the Domain being reviewed (Forest > Domains > Domain). 
Right click on the "Default Domain Policy".
Select Edit.
Navigate to Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Kerberos Policy.

If the "Enforce user logon restrictions" is not set to "Enabled", this is a finding.'
  desc 'fix', 'Configure the policy value in the Default Domain Policy for Computer Configuration ->  Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy -> "Enforce user logon restrictions" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27767r475518_chk'
  tag severity: 'medium'
  tag gid: 'V-226065'
  tag rid: 'SV-226065r569184_rule'
  tag stig_id: 'WN12-AC-000010-DC'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27755r475519_fix'
  tag 'documentable'
  tag legacy: ['SV-51160', 'V-2376']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
