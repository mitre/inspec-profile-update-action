control 'SV-246836' do
  title 'The HYCU server must generate audit records containing information that establishes the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., administrators or processes acting on behalf of administrators) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Event identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.'
  desc 'check', 'Check the contents of the "/var/log/audit/audit.log" file.

HYCU also maintains Event (Audit) information in the "HYCU Web UI Events" menu. 

Verify the audit log contains records showing the identity of an individual or process associated with the event.

If the audit log is not configured or does not have required contents, this is a finding.'
  desc 'fix', 'Log on to the HYCU VM console and load the STIG audit rules by using the following commands. 

1. cp /usr/share/doc/audit/rules/10-base-config.rules /usr/share/doc/audit/rules/30-stig.rules /usr/share/doc/audit/rules/31-privileged.rules /usr/share/doc/audit/rules/99-finalize.rules /etc/audit/rules.d/

2. augenrules --load'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50268r768170_chk'
  tag severity: 'medium'
  tag gid: 'V-246836'
  tag rid: 'SV-246836r768172_rule'
  tag stig_id: 'HYCU-AU-000013'
  tag gtitle: 'SRG-APP-000100-NDM-000230'
  tag fix_id: 'F-50222r768171_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
