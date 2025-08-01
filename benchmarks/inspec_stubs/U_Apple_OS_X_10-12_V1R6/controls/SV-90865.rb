control 'SV-90865' do
  title 'The OS X system must be configured with access control lists (ACLs) for system log files to be set correctly.'
  desc 'System logs should only be readable by root or admin users. System logs frequently contain sensitive information that could be used by an attacker. Setting the correct ACLs mitigates this risk.'
  desc 'check', %q(These commands check for log files that exist on the system and print out the list of ACLs if there are any.

/usr/bin/sudo ls -ld@ $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
/usr/bin/sudo ls -ld@ $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null

ACLs will be listed under any file that may contain them, i.e., "0: group:admin allow list,readattr,reaadextattr,readsecurity".

If any system log file contains this information, this is a finding.)
  desc 'fix', 'For any log file that returns an ACL, run the following command:

/usr/bin/sudo chmod -N [log file]

[log file] is the full path to the log file in question.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75863r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76177'
  tag rid: 'SV-90865r1_rule'
  tag stig_id: 'AOSX-12-002107'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-82815r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
