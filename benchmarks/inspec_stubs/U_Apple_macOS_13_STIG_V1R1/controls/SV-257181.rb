control 'SV-257181' do
  title 'The macOS system must provide an immediate real-time alert to the System Administrator (SA) and Information System Security Officer (ISSO), at a minimum, of all audit failure events requiring real-time alerts.'
  desc 'The audit service must be configured to immediately print messages to the console or email administrator users when an auditing failure occurs. It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.'
  desc 'check', 'Verify the macOS system is configured to print error messages to the console with the following command:

/usr/bin/sudo /usr/bin/grep logger /etc/security/audit_warn

logger -s -p security.warning "audit warning: $type $argument"

If the argument "-s" is missing, or if "audit_warn" has not been otherwise modified to print errors to the console or send email alerts to the SA and ISSO, this is a finding.'
  desc 'fix', %q(Configure the macOS system to print error messages to the console with the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/logger -p/logger -s -p/' /etc/security/audit_warn; /usr/bin/sudo /usr/sbin/audit -s

Alternatively, use a text editor to update the "/etc/security/audit_warn" file.)
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60866r905174_chk'
  tag severity: 'medium'
  tag gid: 'V-257181'
  tag rid: 'SV-257181r905176_rule'
  tag stig_id: 'APPL-13-001031'
  tag gtitle: 'SRG-OS-000344-GPOS-00135'
  tag fix_id: 'F-60807r905175_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
