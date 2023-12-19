control 'SV-214271' do
  title 'The account used to run the Apache web server must not have a valid login shell and password defined.'
  desc 'During installation of the Apache web server software, accounts are created for the Apache web server to operate properly. The accounts installed can have either no password installed or a default password, which will be known and documented by the vendor and the user community.

The first things an attacker will try when presented with a logon screen are the default user identifiers with default passwords. Installed applications may also install accounts with no password, making the logon even easier. Once the Apache web server is installed, the passwords for any created accounts should be changed and documented. The new passwords must meet the requirements for all passwords, i.e., uppercase/lowercase characters, numbers, special characters, time until change, reuse policy, etc. 

Service accounts or system accounts that have no logon capability do not need to have passwords set or changed.'
  desc 'check', 'Identify the account that is running the "httpd" process:
# ps -ef | grep -i httpd | grep -v grep

apache   29613   996  0 Feb17 ?        00:00:00 /usr/sbin/httpd
apache   29614   996  0 Feb17 ?        00:00:00 /usr/sbin/httpd

Check to see if the account has a valid login shell:

# cut -d: -f1,7 /etc/passwd | grep -i <service_account>
apache:/sbin/nologin

If the service account has a valid login shell, verify that no password is configured for the account:

# cut -d: -f1,2 /etc/shadow | grep -i <service_account>
apache:!!

If the account has a valid login shell and a password defined, this is a finding.'
  desc 'fix', 'Update the /etc/passwd file to assign the account used to run the "httpd" process an invalid login shell such as "/sbin/nologin".

Lock the account used to run the "httpd" process:

# passwd -l <account>
Locking password for user <account>
passwd: Success'
  impact 0.7
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15485r277073_chk'
  tag severity: 'high'
  tag gid: 'V-214271'
  tag rid: 'SV-214271r612240_rule'
  tag stig_id: 'AS24-U1-000940'
  tag gtitle: 'SRG-APP-000516-WSR-000079'
  tag fix_id: 'F-15483r277074_fix'
  tag 'documentable'
  tag legacy: ['V-92751', 'SV-102839']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
