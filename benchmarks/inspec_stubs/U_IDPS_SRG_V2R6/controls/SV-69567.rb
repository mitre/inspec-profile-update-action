control 'SV-69567' do
  title 'The IDPS must provide audit record generation with a configurable severity and escalation level capability.'
  desc 'Without the capability to generate audit records with a severity code it is difficult to track and handle detection events.

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.

The IDPS must have the capability to collect and log the severity associated with the policy, rule, or signature. IDPS products often have either pre-configured and/or a configurable method for associating an impact indicator or severity code with signatures and rules, at a minimum.'
  desc 'check', 'Verify the configuration provides audit record generation with a configurable severity and escalation level capability.

If the IDPS does not provide audit record generation with a configurable severity and escalation level capability, this is a finding.'
  desc 'fix', 'Configure the IDPS to provide audit record generation with a configurable severity and escalation level capability.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55943r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55321'
  tag rid: 'SV-69567r2_rule'
  tag stig_id: 'SRG-NET-000113-IDPS-00189'
  tag gtitle: 'SRG-NET-000113-IDPS-00189'
  tag fix_id: 'F-60187r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
