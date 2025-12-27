control 'SV-69653' do
  title 'To protect against unauthorized data mining, the IDPS must detect code injection attacks launched against application objects including, at a minimum, application URLs and application code.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack applications may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. These attacks include buffer overrun, XML, JavaScript, and HTML injections.

IDPS component(s) with anomaly detection must be included in the IDPS implementation. These components must include rules and anomaly detection algorithms to monitor for atypical application behavior, commands, and accesses.'
  desc 'check', 'Verify the IDPS detects code injection attacks launched against application objects including, at a minimum, application URLs and application code.

If the IDPS does not detect code injection attacks launched against application objects including, at a minimum, application URLs and application code, this is a finding.'
  desc 'fix', 'Configure the IDPS to detect code injection attacks launched against application objects including, at a minimum, application URLs and application code.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-56021r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55407'
  tag rid: 'SV-69653r1_rule'
  tag stig_id: 'SRG-NET-000319-IDPS-00185'
  tag gtitle: 'SRG-NET-000319-IDPS-00185'
  tag fix_id: 'F-60271r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
