control 'SV-254120' do
  title 'Nutanix AOS must limit the number of concurrent sessions to ten for all accounts and/or account types.'
  desc 'Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions must be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Verify Nutanix AOS limits the number of concurrent sessions to "10" or less for all accounts and/or account types by issuing the following command:

$ sudo grep "maxlogins" /etc/security/limits.conf 

If the line * hard maxlogins 10, is missing or set to a number more than 10, this is a finding.'
  desc 'fix', 'Modify the file /etc/security/limits.conf and add the line * hard maxlogins 10 or set the number to less than or equal to 10.'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57605r846446_chk'
  tag severity: 'medium'
  tag gid: 'V-254120'
  tag rid: 'SV-254120r846448_rule'
  tag stig_id: 'NUTX-OS-000010'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag fix_id: 'F-57556r846447_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
