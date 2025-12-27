control 'SV-215419' do
  title 'The AIX systems access control program must be configured to grant or deny system access to specific hosts.'
  desc "If the system's access control program is not configured with appropriate rules for allowing and denying access to system network resources, services may be accessible to unauthorized hosts."
  desc 'check', 'Check for the existence of the "/etc/hosts.allow" and "/etc/hosts.deny" files using commands: 

# ls -la /etc/hosts.allow 
-rw-r--r--    1 root     system           11 Jan 28 11:09 /etc/hosts.allow

# ls -la /etc/hosts.deny
-rw-r--r--    1 root     system            0 Jan 28 11:02 /etc/hosts.deny
 
If either file does not exist, this is a finding. 

Check for the presence of a default deny entry using command: 

# grep -E "ALL:[[:blank:]]*ALL" /etc/hosts.deny 
ALL:ALL

If the "ALL: ALL" entry is not present in the "/etc/hosts.deny" file, any TCP service from a host or network not matching other rules will be allowed access. 

If the entry is not in "/etc/hosts.deny", this is a finding.'
  desc 'fix', 'Edit the "/etc/hosts.allow" and "/etc/hosts.deny" files to configure access restrictions.

Add "ALL: ALL" entry to "/etc/hosts.deny" file.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16617r294708_chk'
  tag severity: 'medium'
  tag gid: 'V-215419'
  tag rid: 'SV-215419r508663_rule'
  tag stig_id: 'AIX7-00-003124'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16615r294709_fix'
  tag 'documentable'
  tag legacy: ['V-91685', 'SV-101783']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
