control 'SV-251624' do
  title 'IDMS must suppress security-related messages so that no information is returned that can be exploited.'
  desc 'Error messages issued to non-privileged users may have contents that should be considered confidential. IDMS should be configured so that these messages are not issued to those users.'
  desc 'check', 'Log on to IDMS DC system and issue "DCPROFIL". Scroll to the OPTION FLAGS screen. If "OPT00051" is not listed, this is a finding. 

For IDMS LOG messages, if OPT00226 is not listed, this is a finding.'
  desc 'fix', 'Reassemble, relink, and reload (V NC) RHDCOPTF with #DEFOPTF OPT00051 (for messages sent to user) and optional #DEFOPTF OPT00226 (for messages sent to IDMS log).'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55059r807737_chk'
  tag severity: 'medium'
  tag gid: 'V-251624'
  tag rid: 'SV-251624r807739_rule'
  tag stig_id: 'IDMS-DB-000530'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag fix_id: 'F-55013r807738_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
