control 'SV-32271' do
  title 'Application account passwords must meet DoD requirements for length, complexity and changes.'
  desc 'Setting application accounts to expire may cause applications to stop functioning. The organization must have a policy that manually managed application account passwords are changed at least annually or when a system administrator with knowledge of the password leaves the organization. Application/service account passwords must be at least 15 characters and follow complexity requirements for all passwords.'
  desc 'check', %q(Determine if manually managed application/service accounts exist. If none exist, this is NA.

Verify the organization has a policy to ensure passwords for manually managed application/service accounts are at least 15 characters in length. It must also require the passwords be changed at least annually or when an administrator with knowledge of the password leaves the organization.

If such a policy does not exist or has not been implemented, this is a finding.

Identify manually managed application/service accounts.

To determine the date a password was last changed:

Domain controllers:

Open "Windows PowerShell" with elevated privileges (run as administrator).

Enter "Import-Module ActiveDirectory". (This only needs to be run once during a PowerShell session.)

Enter "Get-ADUser -Identity [application account name] -Properties PasswordLastSet | FL Name, PasswordLastSet", where [application account name] is the name of the manually managed application/service account.

If the "PasswordLastSet" date is more than one year old, this is a finding.

Member servers and standalone systems:

Open "Windows PowerShell" or "Command Prompt".

Enter 'Net User [application account name] | Find /i "Password Last Set"', where [application account name] is the name of the manually managed application/service account.

If the "Password Last Set" date is more than one year old, this is a finding.

Note: Other queries or tools may be used. The organization must be able to demonstrate the results are valid and meet the intent of the requirement.)
  desc 'fix', 'Establish a policy that requires application/service account passwords that are manually managed to be at least 15 characters in length. It must also require the passwords be changed at least annually or when an administrator with knowledge of the password leaves the organization. Ensure the policy is enforced.

Windows automatically addresses passwords for Managed Service Accounts.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-78971r4_chk'
  tag severity: 'medium'
  tag gid: 'V-14271'
  tag rid: 'SV-32271r2_rule'
  tag gtitle: 'Application Account Passwords'
  tag fix_id: 'F-86129r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000205', 'CCI-002142']
  tag nist: ['IA-5 (1) (a)', 'AC-2 (10)']
end
