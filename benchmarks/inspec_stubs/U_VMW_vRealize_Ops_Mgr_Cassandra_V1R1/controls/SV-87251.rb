control 'SV-87251' do
  title 'The Cassandra database must include additional, more detailed, organization-defined information in the audit records for audit events identified by type, location, or subject.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. To support analysis, some types of events will need information to be logged that exceeds the basic requirements of event type, time stamps, location, source, outcome, and user identity. If additional information is not available, it could negatively impact forensic investigations into user actions or other malicious events.

The organization must determine what additional information is required for complete analysis of the audited events. The additional information required is dependent on the type of information (e.g., sensitivity of the data and the environment within which it resides). At a minimum, the organization must employ either full-text recording of privileged commands or the individual identities of group users, or both. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. 

Examples of detailed information the organization may require in audit records are full-text recording of privileged commands or the individual identities of group account users.'
  desc 'check', %q(Review the Cassandra Server settings to ensure additional, more detailed, organization-defined information in the audit records for audit events identified by type, location, or subject are included.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', %q(Configure the Cassandra Server to include additional, more detailed, organization-defined information in the audit records for audit events identified by type, location, or subject.

At the command line execute the following command:

# sed -i 's/^\(\s*\\)<root level=".*">\(\s*\\)$/\1<root level="ALL">\2/' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml)
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72773r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72619'
  tag rid: 'SV-87251r1_rule'
  tag stig_id: 'VROM-CS-000055'
  tag gtitle: 'SRG-APP-000101-DB-000044'
  tag fix_id: 'F-79021r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
