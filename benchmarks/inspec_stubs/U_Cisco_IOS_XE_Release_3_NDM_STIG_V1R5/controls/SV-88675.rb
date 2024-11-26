control 'SV-88675' do
  title 'The Cisco IOS XE router must generate audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Verify that logging is properly configured on the Cisco IOS XE router.

The configuration will look similar to the example below:

logging userinfo

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys

If logging is not configured to log the full-text recording of privileged commands, this is a finding.'
  desc 'fix', 'Enter the following commands to enable auditing:  

logging userinfo

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74085r3_chk'
  tag severity: 'low'
  tag gid: 'V-74001'
  tag rid: 'SV-88675r2_rule'
  tag stig_id: 'CISR-ND-000033'
  tag gtitle: 'SRG-APP-000101-NDM-000231'
  tag fix_id: 'F-80541r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
