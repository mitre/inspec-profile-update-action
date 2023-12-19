control 'SV-96097' do
  title 'The WebSphere Application Server must periodically regenerate LTPA keys.'
  desc 'The encryption of authentication information that is exchanged between servers involves the Lightweight Third-Party Authentication (LTPA) mechanism. LTPA utilizes encryption keys, if LTPA is utilized, the LTPA keys must be regenerated on a regular basis. The time period must be defined, documented and accepted by the ISSO but must be performed at least annually.

Note: If LTPA keys are shared across cells, you must export the keys from the cell where the keys have been regenerated, and import into the cells whose keys have not changed. Instructions for managing the LTPA keys is provided here: https://www.ibm.com/support/knowledgecenter/en/SSAW57_9.0.0/com.ibm.websphere.nd.multiplatform.doc/ae/tsec_sslmanagelptakeys.html'
  desc 'check', 'If LTPA is not utilized, this is not applicable.

Request the documented process to manually regenerate the LTPA keys.

The time period for regeneration must be defined, documented and accepted by the ISSO but must be performed at least annually. 

Review documented process for LTPA key regeneration.

If there is no process to regenerate LTPA keys periodically, this is a finding.'
  desc 'fix', 'These steps must be documented and then executed during the down time scheduled for periodic LTPA key regeneration.

The time period must be defined, documented and accepted by the ISSO but must be performed at least annually.

Navigate to Security >> SSL Certificate and Key Management >> Key set groups.

Check "CellLTPAKeySetGroup".

Click "Generate Keys".

Click "Save".

Then synchronize the changes to all nodes.'
  impact 0.3
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81093r1_chk'
  tag severity: 'low'
  tag gid: 'V-81383'
  tag rid: 'SV-96097r1_rule'
  tag stig_id: 'WBSP-AS-001530'
  tag gtitle: 'SRG-APP-000428-AS-000265'
  tag fix_id: 'F-88169r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
