control 'SV-223485' do
  title 'IBM z/OS Started Tasks must be properly identified and defined to ACF2.'
  desc 'Started procedures have system generated job statements that do not contain the user, group, or password statements. To enable the started procedure to access the same protected resources that users and groups access, started procedures must have an associated USERID. If a USERID is not associated with the started procedure, the started procedure will not have access to the resources.

To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.'
  desc 'check', 'Refer to the site security plan, the system administrator, and system libraries to determine list of stated tasks available on the system.

From the ACF command screen enter:
SET LID 
SET VERBOSE 
LIST IF(STC)

If all logonids identified as started tasks have the STC attribute specified, this is not a finding.'
  desc 'fix', 'All started tasks will be assigned an individual logonid. The logonid for a Started Task Control (STC) will be granted the minimum privileges necessary for the STC to function. In addition to the default LID field settings, all STC logonids will have the following field setting:

STC

Example:
SET LID
INSERT logonid STC'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25158r877322_chk'
  tag severity: 'medium'
  tag gid: 'V-223485'
  tag rid: 'SV-223485r877342_rule'
  tag stig_id: 'ACF2-ES-000670'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25146r504565_fix'
  tag 'documentable'
  tag legacy: ['V-97669', 'SV-106773']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
