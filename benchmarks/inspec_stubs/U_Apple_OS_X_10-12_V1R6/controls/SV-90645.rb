control 'SV-90645' do
  title 'The OS X system must monitor remote access methods and generate audit records when successful/unsuccessful attempts to access/modify privileges occur.'
  desc 'Frequently, an attacker that successfully gains access to a system has only gained access to an account with limited privileges, such as a guest account or a service account. The attacker must attempt to change to another user account with normal or elevated privileges in order to proceed. Auditing successful and unsuccessful attempts to switch to another user account and the escalation of privileges mitigates this risk.

'
  desc 'check', 'To view the currently configured flags for the audit daemon, run the following command:

/usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control

Attempts to log in as another user are logged by way of the "lo" flag.

If "lo" is not listed in the result of the check, this is a finding.'
  desc 'fix', %q(To ensure the appropriate flags are enabled for auditing, run the following command:

/usr/bin/sudo sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.)
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75641r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75957'
  tag rid: 'SV-90645r1_rule'
  tag stig_id: 'AOSX-12-000030'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-82595r1_fix'
  tag satisfies: ['SRG-OS-000032-GPOS-00013', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000462-GPOS-00206']
  tag 'documentable'
  tag cci: ['CCI-000067', 'CCI-000172']
  tag nist: ['AC-17 (1)', 'AU-12 c']
end
