control 'SV-246826' do
  title 'The HYCU VM console must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must block any logon attempt for 15 minutes.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Log on to the HYCU VM console and go to the "/etc/pam.d/" folder. Verify that "password-auth" and "system-auth" contain the following three lines, and the values for deny and unlock_time are as shown.

Commands:
sudo grep pam_faillock.so /etc/pam.d/password-auth
sudo grep pam_faillock.so /etc/pam.d/system-auth

Both should displays the following three lines:
auth        required                                     pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=60 unlock_time=900
auth        required                                     pam_faillock.so authfail audit unlock_time=900
account     required                                     pam_faillock.so

If the required content is not present, this is a finding.'
  desc 'fix', 'Go to the "/etc/pam.d/" folder.

Move the current configuration and make new copies to be edited by executing the following commands:
sudo mv password-auth password-auth-as

sudo mv system-auth system-auth-as

sudo cp password-auth-as password-auth

sudo cp system-auth-as system-auth

Edit the files "password-auth" and "system-auth".

Add the lines:
auth        required                                     pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=60 unlock_time=900
 after line 
auth        required                                     pam_env.so

Add:
auth        required                                     pam_faillock.so authfail audit unlock_time=900
after
auth        sufficient                                   pam_unix.so nullok try_first_pass

Add:
account     required                                     pam_faillock.so
before 
account     required                                     pam_unix.so

The files "system-auth" and "password-auth" are identical, so the procedure can be done on one of the files and copied to the second one.

Restart sssd service:
sudo systemctl restart sssd.service'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50258r768140_chk'
  tag severity: 'medium'
  tag gid: 'V-246826'
  tag rid: 'SV-246826r768142_rule'
  tag stig_id: 'HYCU-AC-000008'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-50212r768141_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
