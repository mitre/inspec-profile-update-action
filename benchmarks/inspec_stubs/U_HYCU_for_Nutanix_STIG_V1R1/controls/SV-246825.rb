control 'SV-246825' do
  title 'The HYCU server and Web UI must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Check the contents of the "/var/log/audit/audit.log" file.

HYCU also maintains Event (Audit) information in the HYCU Web UI Events menu.

Verify the audit log contains records showing when the execution of privileged functions occurred.

If the audit log is not configured or does not have the required contents, this is a finding.'
  desc 'fix', 'Log on to the HYCU VM console and load the STIG audit rules by using the following commands:

1. cp /usr/share/doc/audit/rules/10-base-config.rules /usr/share/doc/audit/rules/30-stig.rules /usr/share/doc/audit/rules/31-privileged.rules /usr/share/doc/audit/rules/99-finalize.rules /etc/audit/rules.d/

2. augenrules --load'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50257r768137_chk'
  tag severity: 'medium'
  tag gid: 'V-246825'
  tag rid: 'SV-246825r768139_rule'
  tag stig_id: 'HYCU-AC-000007'
  tag gtitle: 'SRG-APP-000343-NDM-000289'
  tag fix_id: 'F-50211r768138_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
