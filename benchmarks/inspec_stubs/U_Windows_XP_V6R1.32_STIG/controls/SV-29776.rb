control 'SV-29776' do
  title 'An Auditors group has not been created to restrict access to the Windows Event Logs.'
  desc 'The Security Event Log contains information on security exceptions that occur on the system.  This data is critical for identifying security vulnerabilities and intrusions.  The Application and System logs can also contain information that is critical in assessing security events.  Therefore, these logs must be protected from unauthorized access and modification.  

An Auditors group will be used to restrict access to auditing through the User Right “Manage auditing and security log” (V-1103) and for assigning permissions to event logs (V-1077).

Only individuals who have auditing responsibilities (IAO, IAM, auditors, etc.) should be members of this group.

The individual System Administrators responsible for maintaining this system can also be members of this group.'
  desc 'check', 'Interview the SA to determine if an Auditors group for controlling the Windows Event Logs has been created.
 
 
NOTE:  The administrator(s) responsible for the installation and maintenance of the individual system(s) must be a member(s) of the Auditors group.  This will permit the responsible administrator to enable and configure system auditing, and perform maintenance functions related to the logs.  Administrators who are not responsible for maintenance on an individual system will not be included in the Auditors group.'
  desc 'fix', 'Create an Auditors group for controlling the Windows Event Logs and assign the necessary rights and access controls.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-7886r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1137'
  tag rid: 'SV-29776r1_rule'
  tag gtitle: 'Access Restrictions to Logs'
  tag fix_id: 'F-34r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECTP-1'
end
