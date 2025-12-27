control 'SV-37182' do
  title 'The system must limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements.'
  desc 'Limiting simultaneous user logins can insulate the system from denial of service problems caused by excessive logins.  Automated login processes operating improperly or maliciously may result in an exceptional number of simultaneous login sessions.

If the defined value of 10 logins does not meet operational requirements, the site may define the permitted number of simultaneous login sessions based on operational requirements.

This limit is for the number of simultaneous login sessions for EACH user account.  This is NOT a limit on the total number of simultaneous login sessions on the system.'
  desc 'check', 'Check for a default maxlogins line in the /etc/security/limits.conf and /etc/security/limits.d/* files.

Procedure:
#grep maxlogins /etc/security/limits.conf /etc/security/limits.d/*

The default maxlimits should be set to a max of 10 or a documented site defined number:

* - maxlogins 10

If no such line exists, this is a finding.'
  desc 'fix', 'Add a "maxlogins" line such as "* hard maxlogins 10" to /etc/security/limits.conf or a file in /etc/security/limits.d. The enforced maximum should be defined by site requirements and policy.'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35885r1_chk'
  tag severity: 'low'
  tag gid: 'V-22298'
  tag rid: 'SV-37182r1_rule'
  tag stig_id: 'GEN000450'
  tag gtitle: 'GEN000450'
  tag fix_id: 'F-31140r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
