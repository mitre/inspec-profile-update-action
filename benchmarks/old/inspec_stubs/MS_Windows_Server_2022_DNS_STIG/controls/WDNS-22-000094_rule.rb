control 'WDNS-22-000094_rule' do
  title 'In the event of a system failure, the Windows 2022 DNS Server must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving application state information helps to facilitate application restart and return to the operational mode of the organization with less disruption to mission-essential processes.'
  desc 'check', 'Use the AuditPol tool to review the current Audit Policy configuration:

Open a Command Prompt with elevated privileges ("Run as Administrator").

Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.

Object Access >> File System - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access >> Audit File System with "Failure" selected.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000094_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000094'
  tag rid: 'WDNS-22-000094_rule'
  tag stig_id: 'WDNS-22-000094'
  tag gtitle: 'SRG-APP-000226-DNS-000032'
  tag fix_id: 'F-WDNS-22-000094_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
