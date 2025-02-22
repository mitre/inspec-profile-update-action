control 'SV-252475' do
  title 'The macOS system must provide an immediate real-time alert to the System Administrator (SA) and Information System Security Officer (ISSO), at a minimum, of all audit failure events requiring real-time alerts.'
  desc 'The audit service should be configured to immediately print messages to the console or email administrator users when an auditing failure occurs. It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.'
  desc 'check', 'By default, "auditd" only logs errors to "syslog". To see if audit has been configured to print error messages to the console, run the following command:

/usr/bin/sudo /usr/bin/grep logger /etc/security/audit_warn

If the argument "-s" is missing, or if "audit_warn" has not been otherwise modified to print errors to the console or send email alerts to the SA and ISSO, this is a finding.'
  desc 'fix', %q(To make "auditd" log errors to standard error as well as "syslogd", run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/logger -p/logger -s -p/' /etc/security/audit_warn; /usr/bin/sudo /usr/sbin/audit -s)
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55931r816237_chk'
  tag severity: 'medium'
  tag gid: 'V-252475'
  tag rid: 'SV-252475r853279_rule'
  tag stig_id: 'APPL-12-001031'
  tag gtitle: 'SRG-OS-000344-GPOS-00135'
  tag fix_id: 'F-55881r816238_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
