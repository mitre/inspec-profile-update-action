control 'SV-252947' do
  title 'TOSS must limit the number of concurrent sessions to 256 for all accounts and/or account types.'
  desc 'Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to Denial of Service (DoS) attacks.

TOSS as an HPC operating system, is capable of supporting a large number of sessions, as well as tools which presume a larger number of concurrent sessions will be allowed.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', %q(Verify TOSS limits the number of concurrent sessions to less than or equal to 256 for all accounts and/or account types by issuing the following command:

$ sudo grep -r -s '^[^#].*maxlogins' /etc/security/limits.conf /etc/security/limits.d/*.conf
* hard maxlogins 256

This can be set as a global domain (with the * wildcard) but may be set differently for multiple domains.

If the "maxlogins" item is missing, commented out, or the value is set greater than "256" and is not documented with the Information System Security Officer (ISSO) as an operational requirement for all domains that have the "maxlogins" item assigned, this is a finding.)
  desc 'fix', 'Configure TOSS to limit the number of concurrent sessions to at most 256 for all accounts and/or account types.

Add the following line to the top of the /etc/security/limits.conf or in a ."conf" file defined in /etc/security/limits.d/:

* hard maxlogins 256'
  impact 0.3
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56400r824163_chk'
  tag severity: 'low'
  tag gid: 'V-252947'
  tag rid: 'SV-252947r824165_rule'
  tag stig_id: 'TOSS-04-020010'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag fix_id: 'F-56350r824164_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
