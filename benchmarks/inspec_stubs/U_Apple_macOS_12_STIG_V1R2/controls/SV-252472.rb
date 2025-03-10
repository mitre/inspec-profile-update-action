control 'SV-252472' do
  title 'The macOS system must audit the enforcement actions used to restrict access associated with changes to the system.'
  desc 'By auditing access restriction enforcement, changes to application and OS configuration files can be audited. Without auditing the enforcement of access restrictions, it will be difficult to identify attempted attacks and an audit trail will not be available for forensic investigation.

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.   

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). 

'
  desc 'check', 'To view the currently configured flags for the audit daemon, run the following command:

/usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control

Enforcement actions are logged by way of the "fm" flag, which audits permission changes, and "-fr" and "-fw", which denote failed attempts to read or write to a file, and -fd, which audits failed file deletion.

If "fm", "-fr", "-fw", and "-fd" are not listed in the result of the check, this is a finding.'
  desc 'fix', %q(To set the audit flags to the recommended setting, run the following command to add the flags "fm", "-fr", "-fw", and "-fd" all at once:

/usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,fm,-fr,-fw,-fd/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.)
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55928r816228_chk'
  tag severity: 'medium'
  tag gid: 'V-252472'
  tag rid: 'SV-252472r816468_rule'
  tag stig_id: 'APPL-12-001020'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-55878r816467_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000461-GPOS-00205', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000465-GPOS-00209', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000467-GPOS-00211', 'SRG-OS-000468-GPOS-00212', 'SRG-OS-000474-GPOS-00219']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-001814']
  tag nist: ['AU-12 c', 'CM-5 (1)']
end
