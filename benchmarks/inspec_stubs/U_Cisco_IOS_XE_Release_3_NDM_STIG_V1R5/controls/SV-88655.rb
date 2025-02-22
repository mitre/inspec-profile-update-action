control 'SV-88655' do
  title 'The Cisco IOS XE router must provide audit record generation capability for DoD-defined auditable events within the router.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the network device (e.g., process, module). Certain specific device functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the device will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);
(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and
(iii) All account creation, modification, disabling, and termination actions.'
  desc 'check', 'Verify that the Cisco IOS XE router is generating audit records.

The configuration should look similar to the example below:

logging userinfo
login on-failure log
login on-success log

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys

If audit records are not being generated, this is a finding.'
  desc 'fix', 'Enter the following commands to enable auditing:  

logging userinfo
login on-failure log
login on-success log

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74063r3_chk'
  tag severity: 'low'
  tag gid: 'V-73981'
  tag rid: 'SV-88655r2_rule'
  tag stig_id: 'CISR-ND-000023'
  tag gtitle: 'SRG-APP-000089-NDM-000221'
  tag fix_id: 'F-80521r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
