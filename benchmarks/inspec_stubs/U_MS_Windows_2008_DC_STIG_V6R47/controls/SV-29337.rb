control 'SV-29337' do
  title 'Application account passwords must meet DoD requirements for length, complexity and changes.'
  desc 'Setting application accounts to expire may cause applications to stop functioning. The organization must have a policy that manually managed application account passwords are changed at least annually or when a system administrator with knowledge of the password leaves the organization. Application/service account passwords must be at least 15 characters and follow complexity requirements for all passwords.'
  desc 'check', %q(Determine if manually managed application/service accounts exist. If none exist, this is NA.

Verify the organization has a policy to ensure passwords for manually managed application/service accounts are at least 15 characters in length. It must also require the passwords be changed at least annually or when an administrator with knowledge of the password leaves the organization.

If such a policy does not exist or has not been implemented, this is a finding.

Identify manually managed application/service accounts.

Open a "Command Prompt" with elevated privileges (run as administrator).

Enter 'Net User [application account name] | Find /i "Password Last Set"', where [application account name] is the name of the manually managed application/service account.

If the "Password Last Set" date is more than one year old, this is a finding.

Domain Controllers:

The following may also be used on domain controllers:

Enter “Dsquery user -limit 0 -o rdn -stalepwd 365”.

This will return a list of User Accounts with passwords older the one year.

If any application account is returned as having a password older than one year, this is a finding.

Note: Other queries or tools may be used. The organization must be able to demonstrate the results are valid and meet the intent of the requirement.)
  desc 'fix', 'Establish a policy that requires application/service account passwords that are manually managed to be at least 15 characters in length. It must also require the passwords be changed at least annually or when an administrator with knowledge of the password leaves the organization. Ensure the policy is enforced.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-79569r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14271'
  tag rid: 'SV-29337r2_rule'
  tag gtitle: 'Application Account Passwords'
  tag fix_id: 'F-86707r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000205', 'CCI-002142']
  tag nist: ['IA-5 (1) (a)', 'AC-2 (10)']
end
