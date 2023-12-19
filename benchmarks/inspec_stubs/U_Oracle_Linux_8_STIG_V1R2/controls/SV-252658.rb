control 'SV-252658' do
  title 'OL 8 systems below version 8.4 must ensure the password complexity module in the system-auth file is configured for three retries or less.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.

OL 8 utilizes "pwquality" as a mechanism to enforce password complexity. This is set in both:
/etc/pam.d/password-auth
/etc/pam.d/system-auth
By limiting the number of attempts to meet the pwquality module complexity requirements before returning with an error, the system will audit abnormal attempts at password changes.'
  desc 'check', 'Note: This requirement applies to OL versions 8.0 through 8.3. If the system is OL version 8.4 or newer, this requirement is not applicable.

Verify the operating system is configured to limit the "pwquality" retry option to 3. 

Check for the use of the "pwquality" retry option in the system-auth file with the following command:

$ sudo cat /etc/pam.d/system-auth | grep pam_pwquality

password required pam_pwquality.so retry=3

If the value of "retry" is set to "0" or greater than "3", this is a finding.'
  desc 'fix', 'Configure the operating system to limit the "pwquality" retry option to 3.

Add the following line to the "/etc/pam.d/system-auth" file(or modify the line to have the required value):

password required pam_pwquality.so retry=3'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-56114r818768_chk'
  tag severity: 'medium'
  tag gid: 'V-252658'
  tag rid: 'SV-252658r818770_rule'
  tag stig_id: 'OL08-00-020102'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56064r818769_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
