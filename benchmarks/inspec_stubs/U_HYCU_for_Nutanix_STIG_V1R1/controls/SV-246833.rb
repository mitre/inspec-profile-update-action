control 'SV-246833' do
  title 'The HYCU server must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  desc 'check', 'Check the contents of the "/var/log/audit/audit.log" file.

HYCU also maintains Event (Audit) information in the "HYCU Web UI Events" menu. 

Verify the audit log contains records showing when successful/unsuccessful logon attempts occur.

If the audit log is not configured or does not have required contents, this is a finding.'
  desc 'fix', 'Log on to the HYCU VM console and load the STIG audit rules by using the following commands:

1. cp /usr/share/doc/audit/rules/10-base-config.rules /usr/share/doc/audit/rules/30-stig.rules /usr/share/doc/audit/rules/31-privileged.rules /usr/share/doc/audit/rules/99-finalize.rules /etc/audit/rules.d/

2. augenrules --load'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50265r768161_chk'
  tag severity: 'medium'
  tag gid: 'V-246833'
  tag rid: 'SV-246833r768163_rule'
  tag stig_id: 'HYCU-AU-000005'
  tag gtitle: 'SRG-APP-000503-NDM-000320'
  tag fix_id: 'F-50219r768162_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
