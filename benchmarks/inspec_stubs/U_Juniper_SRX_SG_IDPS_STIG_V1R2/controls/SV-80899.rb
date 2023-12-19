control 'SV-80899' do
  title 'To protect against unauthorized data mining, the Juniper Networks SRX Series Gateway IDPS must prevent code injection attacks launched against application objects, including, at a minimum, application URLs and application code.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack applications may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. These attacks include buffer overrun, XML, JavaScript, and HTML injections.

IDPS component(s) with the capability to prevent code injections must be included in the IDPS implementation to protect against unauthorized data mining. These components must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses.'
  desc 'check', 'Verify attack group is configured.

[edit]
show security idp policies

If an attack group or rule(s) is not implemented to block the packets or terminate the session associated with code injection attacks that could be launched against applications, this is a finding.'
  desc 'fix', 'Configure an attack group for "INJ" and "CMDEXEC" attacks in the signature database which are recommended. Consult the Junos Security Intelligence Center IDP signatures website for a list and details of each attack, along with recommended action upon detection. Then add the attack group to a policy.

Specify the attack group as match criteria in an IDP policy rule. Specify a match criteria and IDP action to block the IP packet or terminate the connection.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67055r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66409'
  tag rid: 'SV-80899r1_rule'
  tag stig_id: 'JUSX-IP-000012'
  tag gtitle: 'SRG-NET-000318-IDPS-00182'
  tag fix_id: 'F-72485r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
