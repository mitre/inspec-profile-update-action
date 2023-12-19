control 'SV-80657' do
  title 'The HP FlexFabric Switch must provide audit record generation capability for DoD-defined auditable events within the HP FlexFabric Switch.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the HP FlexFabric Switch (e.g., process, module). Certain specific device functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the device will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);
(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and
(iii) All account creation, modification, disabling, and termination actions.'
  desc 'check', 'Determine if the HP FlexFabric Switch provides audit record generation capability for DoD-defined auditable events within the HP FlexFabric Switch. The list of events for which the device will provide an audit record generation capability is outlined in the vulnerability discussion.

[HP] display security-logfile summary

 summary  Display summary information of the security log file

 Security log file: Disabled
 Security log file size quota: 10 MB
 Security log file directory: cfa0:/seclog
 Alarm threshold: 80%
 Current usage: 0%
 Writing frequency: 24 hour 0 min 0 sec

If the HP FlexFabric Switch does not provide audit record generation capability for DoD-defined auditable events within the HP FlexFabric Switch, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to provide audit record generation capability for DoD-defined auditable events within the HP FlexFabric Switch.

[HP] info-center security-logfile enable
[HP] info-center security-logfile frequency 30 (in seconds)
[HP] info-center security-logfile size-quota 5 (in MB)
[HP] info-center security-logfile alarm-threshold 90 (in %)'
  impact 0.3
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66813r1_chk'
  tag severity: 'low'
  tag gid: 'V-66167'
  tag rid: 'SV-80657r1_rule'
  tag stig_id: 'HFFS-ND-000022'
  tag gtitle: 'SRG-APP-000089-NDM-000221'
  tag fix_id: 'F-72243r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
