control 'SV-257179' do
  title 'The macOS system must allocate audit record storage capacity to store at least seven days of audit records when audit records are not immediately sent to a central audit record storage facility.'
  desc 'The audit service must be configured to require that records are kept for seven days or longer before deletion when there is no central audit record storage facility. When "expire-after" is set to "7d", the audit service will not delete audit logs until the log data is at least seven days old.'
  desc 'check', 'Verify the macOS system is configured to store at least seven days of audit records with the following command:

/usr/bin/sudo /usr/bin/grep ^expire-after /etc/security/audit_control

expire-after:7d

If "expire-after" is not set to "7d" or greater, this is a finding.'
  desc 'fix', %q(Configure the macOS system to store seven days of audit records with the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*expire-after.*/expire-after:7d/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

Alternatively, use a text editor to update the "/etc/security/audit_control" file.)
  impact 0.3
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60864r905168_chk'
  tag severity: 'low'
  tag gid: 'V-257179'
  tag rid: 'SV-257179r905170_rule'
  tag stig_id: 'APPL-13-001029'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-60805r905169_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
