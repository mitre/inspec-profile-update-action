control 'SV-257169' do
  title 'The macOS system must monitor remote access methods and generate audit records when successful/unsuccessful attempts to access/modify privileges occur.'
  desc 'Frequently, an attacker that successfully gains access to a system has only gained access to an account with limited privileges, such as a guest account or a service account. The attacker must attempt to change to another user account with normal or elevated privileges to proceed. Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

Attempts to log in as another user are logged by way of the "lo" flag.

'
  desc 'check', 'Verify the macOS system is configured to audit attempts to access/modify privileges with the following command:

/usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control

If "lo" is not listed in the result of the check, this is a finding.'
  desc 'fix', %q(Configure the macOS system to audit attempts to access/modify privileges with the following command:

/usr/bin/sudo sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.)
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60854r905138_chk'
  tag severity: 'medium'
  tag gid: 'V-257169'
  tag rid: 'SV-257169r905140_rule'
  tag stig_id: 'APPL-13-001002'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-60795r905139_fix'
  tag satisfies: ['SRG-OS-000032-GPOS-00013', 'SRG-OS-000462-GPOS-00206']
  tag 'documentable'
  tag cci: ['CCI-000067', 'CCI-000172']
  tag nist: ['AC-17 (1)', 'AU-12 c']
end
