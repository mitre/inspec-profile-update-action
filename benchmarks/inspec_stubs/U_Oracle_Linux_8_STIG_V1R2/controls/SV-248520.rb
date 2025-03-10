control 'SV-248520' do
  title 'OL 8 audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events.'
  desc 'Without establishing what type of events occurred and their source, location, and outcome, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack. 
 
Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked. 
 
Associating event types with detected events in OL 8 audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured OL 8 system.

'
  desc 'check', 'Verify the audit service is configured to produce audit records with the following command:

$ sudo systemctl status auditd.service

auditd.service - Security Auditing Service
Loaded:loaded (/usr/lib/systemd/system/auditd.service; enabled; vendor preset: enabled)
Active: active (running) since Tues 2020-12-11 12:56:56 EST; 4 weeks 0 days ago

If the audit service is not "active" and "running", this is a finding.'
  desc 'fix', 'Configure the audit service to produce audit records containing the information needed to establish when (date and time) an event occurred with the following commands:

$ sudo systemctl enable auditd.service

$ sudo systemctl start auditd.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51954r818593_chk'
  tag severity: 'medium'
  tag gid: 'V-248520'
  tag rid: 'SV-248520r818594_rule'
  tag stig_id: 'OL08-00-030181'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-51908r779125_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000051-GPOS-00024', 'SRG-OS-000054-GPOS-00025', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000122-GPOS-00063', 'SRG-OS-000254-GPOS-00095', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000337-GPOS-00129', 'SRG-OS-000348-GPOS-00136', 'SRG-OS-000349-GPOS-00137', 'SRG-OS-000350-GPOS-00138', 'SRG-OS-000351-GPOS-00139', 'SRG-OS-000352-GPOS-00140', 'SRG-OS-000353-GPOS-00141', 'SRG-OS-000354-GPOS-00142', 'SRG-OS-000358-GPOS-00145', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000475-GPOS-00220']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000154', 'CCI-000158', 'CCI-000169', 'CCI-000172', 'CCI-001464', 'CCI-001487', 'CCI-001814', 'CCI-001875', 'CCI-001876', 'CCI-001877', 'CCI-001878', 'CCI-001879', 'CCI-001880', 'CCI-001881', 'CCI-001882', 'CCI-001889', 'CCI-001914', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-6 (4)', 'AU-7 (1)', 'AU-12 a', 'AU-12 c', 'AU-14 (1)', 'AU-3 f', 'CM-5 (1)', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 b', 'AU-7 b', 'AU-8 b', 'AU-12 (3)', 'MA-4 (1) (a)']
end
