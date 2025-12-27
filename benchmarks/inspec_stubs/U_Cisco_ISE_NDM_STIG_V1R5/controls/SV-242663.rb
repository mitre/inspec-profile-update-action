control 'SV-242663' do
  title 'The Cisco ISE must generate audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Verify the logging categories as required by the SSP based on mission requirements for Cisco ISE are configured.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Click the radio button for each logging category and verify it is set. Verify all categories required by the SSP are set. Verify the appropriate severity level (usually WARNING is set).

If the logging category required by the SSP is not configured and sent to the central syslog server target, this is a finding.'
  desc 'fix', 'Enable the logging categories as required by the SSP based on mission requirements for Cisco ISE to send auditable events to the syslog target.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Click the radio button next to the Administrative and Operational Audit logging category and then click "Edit".
3. Choose INFO from the Log Severity Level drop-down list.
4. In the Targets field, move the syslog target name that is being used to the Selected box.
5. Repeat steps 2 and 3 with the selection of other category levels required based on organizational mission and SSP.
6. Click "Save".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45938r714297_chk'
  tag severity: 'medium'
  tag gid: 'V-242663'
  tag rid: 'SV-242663r879569_rule'
  tag stig_id: 'CSCO-NM-000720'
  tag gtitle: 'SRG-APP-000101-NDM-000231'
  tag fix_id: 'F-45895r714298_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
