control 'SV-218059' do
  title 'The system must limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements.'
  desc 'Limiting simultaneous user logins can insulate the system from denial of service problems caused by excessive logins. Automated login processes operating improperly or maliciously may result in an exceptional number of simultaneous login sessions.'
  desc 'check', 'Run the following command to ensure the "maxlogins" value is configured for all users on the system:

$ grep "maxlogins" /etc/security/limits.conf /etc/security/limits.d/*.conf

You should receive output similar to the following:

* hard maxlogins 10

If it is not similar, this is a finding.'
  desc 'fix', 'Limiting the number of allowed users and sessions per user can limit risks related to denial of service attacks. This addresses concurrent sessions for a single account and does not address concurrent sessions by a single user via multiple accounts. To set the number of concurrent sessions per user add the following line in "/etc/security/limits.conf": 

* hard maxlogins 10

A documented site-defined number may be substituted for 10 in the above.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19540r377192_chk'
  tag severity: 'low'
  tag gid: 'V-218059'
  tag rid: 'SV-218059r603264_rule'
  tag stig_id: 'RHEL-06-000319'
  tag gtitle: 'SRG-OS-000027'
  tag fix_id: 'F-19538r377193_fix'
  tag 'documentable'
  tag legacy: ['SV-50485', 'V-38684']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
