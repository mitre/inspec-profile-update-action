control 'SV-258860' do
  title 'The Photon operating system must audit logon attempts for unknown users.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc 'check', %q(At the command line, run the following command to verify that audit logon attempts for unknown users is performed:

# grep '^audit' /etc/security/faillock.conf

Example result:

audit

If the "audit" option is not set, is missing or commented out, this is a finding.

Note: If faillock.conf is not used to configure pam_faillock.so then these options may be specified on the faillock lines in the system-auth and system-account files.)
  desc 'fix', 'Navigate to and open:

/etc/security/faillock.conf

Add or update the following lines:

audit

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Photon OS 4.0'
  tag check_id: 'C-62600r933639_chk'
  tag severity: 'medium'
  tag gid: 'V-258860'
  tag rid: 'SV-258860r933641_rule'
  tag stig_id: 'PHTN-40-000194'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-62509r933640_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
