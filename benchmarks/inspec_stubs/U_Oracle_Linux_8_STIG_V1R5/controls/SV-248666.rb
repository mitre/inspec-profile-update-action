control 'SV-248666' do
  title 'OL 8 must limit the number of concurrent sessions to 10 for all accounts and/or account types.'
  desc 'Operating system management includes the ability to control the number of users and user sessions that use an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to denial-of-service attacks. 
 
This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system.'
  desc 'check', 'Verify the operating system limits the number of concurrent sessions to 10 for all accounts and/or account types by issuing the following command: 
 
$ sudo grep "maxlogins" /etc/security/limits.conf /etc/security/limits.d/*.conf 
 
* hard maxlogins 10 
 
This can be set as a global domain (with the * wildcard) but may be set differently for multiple domains. 
 
If the "maxlogins" item is missing or commented out, or the value is not set to "10" or less for all domains that have the "maxlogins" item assigned, this is a finding.'
  desc 'fix', 'Configure OL 8 to limit the number of concurrent sessions to 10 for all accounts and/or account types. 
 
Add the following line to the top of "/etc/security/limits.conf" or in a ".conf" file defined in "/etc/security/limits.d/": 
 
* hard maxlogins 10'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52100r779562_chk'
  tag severity: 'low'
  tag gid: 'V-248666'
  tag rid: 'SV-248666r877399_rule'
  tag stig_id: 'OL08-00-020024'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag fix_id: 'F-52054r779563_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
