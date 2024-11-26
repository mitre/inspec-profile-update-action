control 'SV-108705' do
  title 'A unique database name and a unique MySQL user with a secure password must be created for use in Jamf Pro EMM.'
  desc 'If the default MySQL database name and password are not changed an adversary could gain unauthorized access to the application which could lead to the compromise of sensitive DoD data.

SFR ID: FMT_SMF.1(2)b. / IA-5(1)(c)

'
  desc 'check', 'Verify a unique database name and a unique MySQL user with a secure password have been created for use in Jamf Pro EMM.

1. Execute the show databases command.
- Ensure at least one database name other than the default databases exits. The default databases are:
infomation_schema
mysql
performance_schema
sys

2. Verify there is a unique MySQL user.
- In MySQL, run select * mysql.user;
- Look for a user that is not Root or one of the other MySQL service accounts.

Both of these steps must be correct.

If a unique database name and a unique MySQL user with a secure password have not been created, this is a finding.'
  desc 'fix', 'Create a unique database name and a unique MySQL user with a secure password. The procedure is found in the following Jamf Knowledge Base article:

https://www.jamf.com/jamf-nation/articles/542/title'
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98451r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99601'
  tag rid: 'SV-108705r1_rule'
  tag stig_id: 'JAMF-10-100080'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-105285r1_fix'
  tag satisfies: ['SRG-APP-000171']
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
