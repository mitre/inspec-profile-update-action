control 'SV-257182' do
  title 'The macOS system must generate audit records for DOD-defined events such as successful/unsuccessful logon attempts, successful/unsuccessful direct access attempts, starting and ending time for user access, and concurrent logons to the same account from different sources.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

Logon events are logged by way of the "aa" flag.

'
  desc 'check', 'Verify the macOS system is configured to audit logon events with the following command:

/usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control

If "aa" is not listed in the result of the check, this is a finding.'
  desc 'fix', %q(Configure the macOS system to audit logon events with the following command:

/usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,aa/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.)
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60867r905177_chk'
  tag severity: 'medium'
  tag gid: 'V-257182'
  tag rid: 'SV-257182r905179_rule'
  tag stig_id: 'APPL-13-001044'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag fix_id: 'F-60808r905178_fix'
  tag satisfies: ['SRG-OS-000470-GPOS-00214', 'SRG-OS-000472-GPOS-00217', 'SRG-OS-000473-GPOS-00218', 'SRG-OS-000475-GPOS-00220']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
