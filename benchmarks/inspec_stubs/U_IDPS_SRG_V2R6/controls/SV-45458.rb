control 'SV-45458' do
  title 'The IDPS must provide audit record generation capability for events where communication traffic is blocked or restricted based on policy filters, rules, signatures, and anomaly analysis.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.

The IDPS must have the capability to capture and log events where communications traffic was blocked or restricted because of a security violation or potential security violations.'
  desc 'check', 'Verify the configuration provides audit record generation capability for events where communication traffic is blocked or restricted based on policy filters, rules, signatures, and anomaly analysis algorithms.

If the IDPS does not provide audit record generation capability for events where communication traffic is blocked or restricted based on policy filters, rules, signatures, and anomaly analysis, this is a finding.'
  desc 'fix', 'Configure the IDPS to provide audit record generation capability for events where communication traffic is blocked or restricted based on policy filters, rules, signatures, and anomaly analysis algorithms.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-42808r2_chk'
  tag severity: 'medium'
  tag gid: 'V-34594'
  tag rid: 'SV-45458r2_rule'
  tag stig_id: 'SRG-NET-000113-IDPS-00082'
  tag gtitle: 'SRG-NET-000113-IDPS-00082'
  tag fix_id: 'F-38855r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
