control 'SV-217114' do
  title 'The SUSE operating system must lock an account after three consecutive invalid access attempts.'
  desc 'By limiting the number of failed access attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

The pam_tally2.so module maintains a count of attempted accesses. This includes user name entry into a logon field as well as password entry. With counting access attempts, it is possible to lock an account without presenting a password into the password field. This should be taken into consideration as it poses as an avenue for denial of service.'
  desc 'check', 'Verify the SUSE operating system locks a user account after three consecutive failed access attempts until the locked account is released by an administrator. 

Check that the system locks a user account after three consecutive failed login attempts using the following command: 

# grep pam_tally2.so /etc/pam.d/common-auth 
auth required pam_tally2.so onerr=fail deny=3 

If no line is returned or the line is commented out, this is a finding.

If the line is missing "onerr=fail", this is a finding.

If the line has "deny" set to a value other than 1, 2, or 3, this is a finding.

Check that the system resets the failed login attempts counter after a successful login using the following command: 

# grep pam_tally2.so /etc/pam.d/common-account 
account required pam_tally2.so 

If the account option is missing, or commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to lock an account when three unsuccessful access attempts occur.

Modify the first line of the auth section "/etc/pam.d/common-auth" file to match the following lines:

auth required pam_tally2.so onerr=fail silent audit deny=3

Add or modify the following line in the /etc/pam.d/common-account file:
account required pam_tally2.so 

Note: Manual changes to the listed files may be overwritten by the "pam-config" program. The "pam-config" program should not be used to update the configurations listed in this requirement.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-36358r602675_chk'
  tag severity: 'medium'
  tag gid: 'V-217114'
  tag rid: 'SV-217114r603262_rule'
  tag stig_id: 'SLES-12-010130'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-36321r602676_fix'
  tag 'documentable'
  tag legacy: ['SV-91767', 'V-77071']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
