control 'SV-258859' do
  title 'The Photon operating system must prevent leaking information of the existence of a user account.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

If the pam_faillock.so module is not configured to use the silent flag it could leak information about the existence or nonexistence of a user account.'
  desc 'check', %q(At the command line, run the following command to verify account information is not leaked during the login process:

# grep '^silent' /etc/security/faillock.conf

Example result:

silent

If the "silent" option is not set, is missing or commented out, this is a finding.

Note: If faillock.conf is not used to configure pam_faillock.so then these options may be specified on the faillock lines in the system-auth and system-account files.)
  desc 'fix', 'Navigate to and open:

/etc/security/faillock.conf

Add or update the following lines:

silent

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Photon OS 4.0'
  tag check_id: 'C-62599r933636_chk'
  tag severity: 'medium'
  tag gid: 'V-258859'
  tag rid: 'SV-258859r933638_rule'
  tag stig_id: 'PHTN-40-000193'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-62508r933637_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
