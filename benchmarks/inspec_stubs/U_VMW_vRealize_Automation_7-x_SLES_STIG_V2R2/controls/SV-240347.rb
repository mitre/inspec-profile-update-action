control 'SV-240347' do
  title 'The SLES for vRealize must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Run the following command to ensure that the operating system enforces the limit of three consecutive invalid logon attempts by a user:

# grep pam_tally2.so /etc/pam.d/common-auth

The output should contain "deny=3" in the returned line.

If this is not the case, this is a finding.

Expected Result:
auth    required       pam_tally2.so deny=3 onerr=fail even_deny_root unlock_time=86400 root_unlock_time=300'
  desc 'fix', 'To configure the SLES for vRealize to enforce the limit of three consecutive invalid attempts using "pam_tally2.so", modify the content of the /etc/pam.d/common-auth-vmware.local by running the following command:

# sed -i "/^[^#]*pam_tally2.so/ c\\auth required pam_tally2.so deny=3 onerr=fail even_deny_root unlock_time=86400 root_unlock_time=300" /etc/pam.d/common-auth-vmware.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43580r670780_chk'
  tag severity: 'medium'
  tag gid: 'V-240347'
  tag rid: 'SV-240347r670782_rule'
  tag stig_id: 'VRAU-SL-000025'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-43539r670781_fix'
  tag 'documentable'
  tag legacy: ['SV-100121', 'V-89471']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
