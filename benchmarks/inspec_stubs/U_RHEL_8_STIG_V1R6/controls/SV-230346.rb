control 'SV-230346' do
  title 'RHEL 8 must limit the number of concurrent sessions to ten for all accounts and/or account types.'
  desc 'Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system.'
  desc 'check', %q(Verify the operating system limits the number of concurrent sessions to "10" for all accounts and/or account types by issuing the following command:

$ sudo grep -r -s '^[^#].*maxlogins' /etc/security/limits.conf /etc/security/limits.d/*.conf

* hard maxlogins 10

This can be set as a global domain (with the * wildcard) but may be set differently for multiple domains.

If the "maxlogins" item is missing, commented out, or the value is set greater than "10" and is not documented with the Information System Security Officer (ISSO) as an operational requirement for all domains that have the "maxlogins" item assigned, this is a finding.)
  desc 'fix', 'Configure the operating system to limit the number of concurrent sessions to "10" for all accounts and/or account types.

Add the following line to the top of the /etc/security/limits.conf or in a ".conf" file defined in /etc/security/limits.d/:

* hard maxlogins 10'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-33015r567784_chk'
  tag severity: 'low'
  tag gid: 'V-230346'
  tag rid: 'SV-230346r627750_rule'
  tag stig_id: 'RHEL-08-020024'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag fix_id: 'F-32990r619863_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
