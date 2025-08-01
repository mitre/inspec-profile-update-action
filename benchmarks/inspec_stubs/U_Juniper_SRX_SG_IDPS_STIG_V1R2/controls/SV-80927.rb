control 'SV-80927' do
  title 'The Juniper Networks SRX Series Gateway IDPS must send an immediate alert to, at a minimum, the Security Control Auditor (SCA) when malicious code is detected.'
  desc 'Without an alert, security personnel may be unaware of an impending failure of the audit capability, and the ability to perform forensic analysis and detect rate-based and other anomalies will be impeded.

The IDPS generates an immediate (within seconds) alert which notifies designated personnel of the incident. Sending a message to an unattended log or console does not meet this requirement since that will not be seen immediately. These messages should include a severity level indicator or code as an indicator of the criticality of the incident.'
  desc 'check', 'Verify an alert is sent when malicious code is detected.

[edit]
show security idp policy

View the rulebase options for the IDP policies.

If the rulebase options for the IDP policies that detect malicious code do not contain the "alert" option, this is a finding.'
  desc 'fix', 'This requirement can be met using an alert. Alerts must be enabled and configured and then added to the IDP policy rulebase command as an option. The following is an example of the command that can be added to the IDP policy. The policy is called Malicious-Activity and the rule is called R1 in this example.

[edit]
set security idp idp-policy Malicious-Activity rulebase-ips rule R1 then notification log-attacks alert'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67083r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66437'
  tag rid: 'SV-80927r1_rule'
  tag stig_id: 'JUSX-IP-000029'
  tag gtitle: 'SRG-NET-000249-IDPS-00222'
  tag fix_id: 'F-72513r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
