control 'SV-251626' do
  title 'IDMS must reveal security-related messages only to authorized users.'
  desc 'Error messages issued to non-privileged users may have contents that should be considered confidential. IDMS should be configured so that these messages are not issued to those users.'
  desc 'check', 'Check that security messages from external security managers (ESMs) are sent only to the log which can be secured. Log on to IDMS DC system and issue "DCPROFIL". Scroll to the "OPTION FLAGS" screen.

If OPT00051 is not listed, this is a finding. 

For IDMS LOG messages, if OPT00226 is not listed, this is a finding. 

Contact the security office and verify that the user, groups, and roles are defined to the ESM so that DC log can only be viewed by Information System Security Officer (ISSO), Information System Security manager (ISSM), Systems Administrator (SA), and Database Administrator (DBA).'
  desc 'fix', 'In the source for RHDCOPTF, add lines: 

         #DEFOPT OPT00051              <-for messages sent to user
         #DEFOPT OPT00226              <-for messages sent to IDMS log

Then, reassemble and relink RHDCOPTF. Reload RHDCOPTF in the CV by issuing the following commands:

DCMT VARY NUCLEUS MODULE RHDCOPTF NEW COPY 
DCMT VARY NUCLEUS RELOAD

Contact the security office to ensure that ADSOBPLG, the ADS print log utility, is secured via the ESM and assigned to the appropriate users, and that the ADS log file is secured from being read by others than ISSO, ISSM, SA, and DBA, also via the ESM.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55061r807743_chk'
  tag severity: 'medium'
  tag gid: 'V-251626'
  tag rid: 'SV-251626r807745_rule'
  tag stig_id: 'IDMS-DB-000550'
  tag gtitle: 'SRG-APP-000267-DB-000163'
  tag fix_id: 'F-55015r807744_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
