control 'SV-258802' do
  title 'The Photon operating system must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc 'check', %q(At the command line, run the following commands to verify accounts are locked after three consecutive invalid logon attempts by a user during a 15-minute time period:

# grep '^deny =' /etc/security/faillock.conf

Example result:

deny = 3

If the "deny" option is not set to "3" or less (but not "0"), is missing or commented out, this is a finding.

# grep '^fail_interval =' /etc/security/faillock.conf

Example result:

fail_interval = 900

If the "fail_interval" option is not set to "900" or more, is missing or commented out, this is a finding.

Note: If faillock.conf is not used to configure the "pam_faillock.so" module, then these options may be specified on the faillock lines in the system-auth and system-account PAM files.)
  desc 'fix', 'Navigate to and open:

/etc/security/faillock.conf

Add or update the following lines:

deny = 3
fail_interval = 900

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Photon OS 4.0'
  tag check_id: 'C-62542r933465_chk'
  tag severity: 'medium'
  tag gid: 'V-258802'
  tag rid: 'SV-258802r933467_rule'
  tag stig_id: 'PHTN-40-000004'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-62451r933466_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
