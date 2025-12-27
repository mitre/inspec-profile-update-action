control 'SV-255962' do
  title 'The Arista network device must be configured to capture all DOD auditable events.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.

'
  desc 'check', 'Verify the Arista network device is configured to audit all DOD auditable events.

Verify the logging settings in the configuration file with the following example:

switch#sh running-config | section logging

logging buffered informational
logging trap informational

NOTE: Acceptable settings include debugging, informational, and notifications to adjust syslog server traffic impact. Setting to higher severity levels can cause necessary lower-level events to be missed.

If the Arista network device is not configured to audit all DOD auditable events, this is a finding.'
  desc 'fix', 'Configure a logging level sufficient to capture all DOD auditable events.

switch(config)#logging buffered informational
switch(config)#logging trap informational

NOTE: Acceptable settings include debugging, informational, and notifications to adjust syslog server traffic impact. Setting to higher severity levels can cause necessary lower-level events to be missed.'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59638r882226_chk'
  tag severity: 'medium'
  tag gid: 'V-255962'
  tag rid: 'SV-255962r882228_rule'
  tag stig_id: 'ARST-ND-000790'
  tag gtitle: 'SRG-APP-000095-NDM-000225'
  tag fix_id: 'F-59581r882227_fix'
  tag satisfies: ['SRG-APP-000095-NDM-000225', 'SRG-APP-000096-NDM-000226', 'SRG-APP-000097-NDM-000227', 'SRG-APP-000098-NDM-000228', 'SRG-APP-000099-NDM-000229', 'SRG-APP-000100-NDM-000230', 'SRG-APP-000516-NDM-000334', 'SRG-APP-000357-NDM-000293', 'SRG-APP-000360-NDM-000295', 'SRG-APP-000505-NDM-000322']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000169', 'CCI-000172', 'CCI-001487', 'CCI-001849', 'CCI-001858']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-12 a', 'AU-12 c', 'AU-3 f', 'AU-4', 'AU-5 (2)']
end
