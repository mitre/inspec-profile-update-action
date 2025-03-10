control 'SV-29199' do
  title 'ACLs for event logs do not conform to minimum requirements.'
  desc 'Event logs are susceptible to unauthorized, and possibly anonymous, tampering if proper ACLs are not applied.'
  desc 'check', 'The event log files “AppEvent.Evt,” “SecEvent.Evt,” and “SysEvent.Evt”— by default, all found in the “%SystemRoot%\\SYSTEM32\\CONFIG” directory. They may have been moved to another folder. 

Check for the following permissions: 
Administrators RX 
(Auditor’s group) All 
SYSTEM All
 
Note:  See V-1137 for the Auditors group requirement.  

The “Auditors” group may appear in the Gold Disk output as a finding. This is because the name of the group is left to the sites. If an auditors group is present, its presence doesn’t constitute a finding.

If the permissions for these files are not as restrictive as the ACL listed, then this is a finding.'
  desc 'fix', 'Set the ACL permissions on the event logs as defined in the manual check.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-4328r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1077'
  tag rid: 'SV-29199r1_rule'
  tag gtitle: 'Incorrect ACLs for event logs'
  tag fix_id: 'F-46r1_fix'
  tag false_positives: 'The “Auditors” group may appear as a finding.  This is because the name of the group is left to the site.  If an auditors group is present, its presence doesn’t constitute a finding.'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECTP-1'
end
