control 'SV-102399' do
  title 'The SEL-2740S must be configured to send log data to a syslog server for the purpose of forwarding alerts to the administrators and the ISSO.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of accounts and notifies administrators and Information System Security Officers (ISSOs). Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', %q(To ensure SEL-2740S Syslog servers are configured do the following:
1. Log in with Permission Level 3 rights into parent OTSDN Controller.
2. Download the latest settings for the SEL-2740S device under test (DUT).
3. Go to the "Configuration Object" page and select the desired switch node.
4. Check the log services settings and confirm the desired Syslog Server IP addresses and severity levels are in the settings fields.
5. Check Syslog flows exist and are accurate for the SEL-2740S DUT and additional neighbor devices' flows exist and are correct.

If the SEL-2740S is not configured with Syslog server entries to ensure auditability, this is a finding.)
  desc 'fix', 'To configure the SEL-2740S to send logs to Syslog servers do the following:
1. Log in with Permission Level 3 right into parent OTSDN Controller.
2. Go to the "Configuration Objects" settings page and select the desired switch for SEL-2740S node.
3. Insert the Syslog log service and configure the settings with the desired Server IP addresses into the Syslog settings fields.
4. Create the flow rules necessary for Syslog.'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch NDM'
  tag check_id: 'C-91607r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92311'
  tag rid: 'SV-102399r1_rule'
  tag stig_id: 'SELS-ND-001430'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-98549r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
