control 'SV-209550' do
  title 'The macOS system must monitor remote access methods and generate audit records when successful/unsuccessful attempts to access/modify privileges occur.'
  desc 'Frequently, an attacker that successfully gains access to a system has only gained access to an account with limited privileges, such as a guest account or a service account. The attacker must attempt to change to another user account with normal or elevated privileges in order to proceed. Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'To view the currently configured flags for the audit daemon, run the following command:

/usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control

Attempts to log in as another user are logged by way of the "lo" flag.

If "lo" is not listed in the result of the check, this is a finding.'
  desc 'fix', %q(To ensure the appropriate flags are enabled for auditing, run the following command:

/usr/bin/sudo sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9801r466258_chk'
  tag severity: 'medium'
  tag gid: 'V-209550'
  tag rid: 'SV-209550r610285_rule'
  tag stig_id: 'AOSX-14-001002'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-9801r466259_fix'
  tag satisfies: ['SRG-OS-000032-GPOS-00013', 'SRG-OS-000462-GPOS-00206']
  tag 'documentable'
  tag legacy: ['SV-104973', 'V-95835']
  tag cci: ['CCI-000067', 'CCI-000172']
  tag nist: ['AC-17 (1)', 'AU-12 c']
end
