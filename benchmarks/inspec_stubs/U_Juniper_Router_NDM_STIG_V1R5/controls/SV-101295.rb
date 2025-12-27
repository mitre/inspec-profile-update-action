control 'SV-101295' do
  title 'The Juniper router must be configured to send log data to a syslog server for the purpose of forwarding alerts to the administrators and the ISSO.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of accounts and notifies administrators and Information System Security Officers (ISSOs). Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'Verify that the router is configured to send logs to a syslog server.  The configuration should look similar to the example below:

system {
   syslog {
        host x.x.x.x {
            any info;
        }
    }

If the router is not configured to send log data to the syslog server, this is a finding.'
  desc 'fix', 'Configure the router to send log data to a syslog server as shown in the example below.

set syslog host x.x.x.x any info'
  impact 0.7
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-90349r2_chk'
  tag severity: 'high'
  tag gid: 'V-91195'
  tag rid: 'SV-101295r2_rule'
  tag stig_id: 'JUNI-ND-001440'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-97393r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
