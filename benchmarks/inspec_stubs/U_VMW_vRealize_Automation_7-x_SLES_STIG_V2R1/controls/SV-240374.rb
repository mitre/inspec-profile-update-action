control 'SV-240374' do
  title 'The SLES for vRealize audit system must be configured to audit all attempts to alter /var/log/lastlog.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the operating system will provide an audit record generation capability as the following: 

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

3) All account creations, modifications, disabling, and terminations; and 

4) All kernel module load, unload, and restart actions.'
  desc 'check', 'Verify that attempts to alter the log files /var/log/lastlog are audited:

# egrep "lastlog" /etc/audit/audit.rules

If "-w /var/log/lastlog -p wa" entry does not exist, this is a finding.'
  desc 'fix', "Ensure attempts to alter /var/log/lastlog are audited by modifying /etc/audit/audit.rules to contain -w /var/log/lastlog -p wa with the following command:

echo '-w /var/log/lastlog -p wa' >> /etc/audit/audit.rules

Or run the following command to implement all logging requirements:

# /etc/dodscript.sh"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43607r670861_chk'
  tag severity: 'medium'
  tag gid: 'V-240374'
  tag rid: 'SV-240374r767042_rule'
  tag stig_id: 'VRAU-SL-000230'
  tag gtitle: 'VRAU-SL-000230'
  tag fix_id: 'F-43566r670862_fix'
  tag 'documentable'
  tag legacy: ['SV-100175', 'V-89525']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
