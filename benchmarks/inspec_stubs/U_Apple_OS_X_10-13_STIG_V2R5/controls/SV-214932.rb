control 'SV-214932' do
  title 'The macOS system must audit the enforcement actions used to restrict access associated with changes to the system.'
  desc 'By auditing access restriction enforcement, changes to application and OS configuration files can be audited. Without auditing the enforcement of access restrictions, it will be difficult to identify attempted attacks and an audit trail will not be available for forensic investigation.

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.

'
  desc 'check', 'To view the currently configured flags for the audit daemon, run the following command:

/usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control

Enforcement actions are logged by way of the "fm" flag, which audits permission changes, and "-fr" and "-fw", which denote failed attempts to read or write to a file.

If "fm", "-fr", and "-fw" are not listed in the result of the check, this is a finding.'
  desc 'fix', %q(To set the audit flags to the recommended setting, run the following command to add the flags "fm", "-fr", and "-fw" all at once:

/usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,fm,-fr,-fw/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16132r397368_chk'
  tag severity: 'medium'
  tag gid: 'V-214932'
  tag rid: 'SV-214932r609363_rule'
  tag stig_id: 'AOSX-13-002110'
  tag gtitle: 'SRG-OS-000365-GPOS-00152'
  tag fix_id: 'F-16130r397369_fix'
  tag satisfies: ['SRG-OS-000365-GPOS-00152', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000461-GPOS-00205', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000465-GPOS-00209', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000467-GPOS-00211', 'SRG-OS-000468-GPOS-00212', 'SRG-OS-000474-GPOS-00219']
  tag 'documentable'
  tag legacy: ['SV-96459', 'V-81745']
  tag cci: ['CCI-000172', 'CCI-001814']
  tag nist: ['AU-12 c', 'CM-5 (1)']
end
