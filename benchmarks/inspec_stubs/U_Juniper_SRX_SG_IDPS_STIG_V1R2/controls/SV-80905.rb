control 'SV-80905' do
  title 'To protect against unauthorized data mining, the Juniper Networks SRX Series Gateway IDPS must detect code injection attacks launched against application objects, including, at a minimum, application URLs and application code.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack applications may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. These attacks include buffer overrun, XML, JavaScript, and HTML injections.

IDPS component(s) with anomaly detection must be included in the IDPS implementation. These components must include rules and anomaly detection algorithms to monitor for atypical application behavior, commands, and accesses.'
  desc 'check', 'Verify an attack group or rule is configured.

[edit]
show security idp policies

If an attack group or rule(s) is not implemented to monitor for code injection attacks that could be launched against application objects, this is a finding.'
  desc 'fix', 'Configure an attack group for "INJ", "SQL", and "CMDEXEC" attacks in the signature database which are recommended. Consult the Junos Security Intelligence Center IDP signatures website for a list and details of each attack, along with recommended action upon detection. Then add the attack group to a policy.

Specify the attack group as match criteria in an IDP policy rule.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67061r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66415'
  tag rid: 'SV-80905r1_rule'
  tag stig_id: 'JUSX-IP-000015'
  tag gtitle: 'SRG-NET-000319-IDPS-00185'
  tag fix_id: 'F-72491r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
