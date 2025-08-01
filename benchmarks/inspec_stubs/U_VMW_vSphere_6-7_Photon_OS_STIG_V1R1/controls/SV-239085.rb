control 'SV-239085' do
  title 'The Photon operating system audit log must log space limit problems to syslog.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

'
  desc 'check', 'At the command line, execute the following command:

# grep "^space_left_action" /etc/audit/auditd.conf

Expected result:

space_left_action = SYSLOG

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/audit/auditd.conf with a text editor.

Ensure that the "space_left_action" line is uncommented and set to the following:

space_left_action = SYSLOG

At the command line, execute the following command:

# service auditd reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42296r675061_chk'
  tag severity: 'medium'
  tag gid: 'V-239085'
  tag rid: 'SV-239085r675063_rule'
  tag stig_id: 'PHTN-67-000013'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-42255r675062_fix'
  tag satisfies: ['SRG-OS-000046-GPOS-00022', 'SRG-OS-000344-GPOS-00135']
  tag 'documentable'
  tag cci: ['CCI-000139', 'CCI-001858']
  tag nist: ['AU-5 a', 'AU-5 (2)']
end
