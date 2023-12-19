control 'SV-77389' do
  title 'Riverbed Optimization System (RiOS) must generate audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Verify that RiOS is configured to generate audit records containing the full-text recording of privileged commands

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Logging

Verify that "Minimum Severity" is set to "info"

If the "Minimum Severity" is not set to "info", this is a finding.'
  desc 'fix', 'Configure RiOS to generate audit records containing the full-text recording of privileged commands

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Logging

Set "Minimum Severity" to "info"
Click "Apply"
Navigate to the top of the screen and click "Save"'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63665r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62899'
  tag rid: 'SV-77389r1_rule'
  tag stig_id: 'RICX-DM-000049'
  tag gtitle: 'SRG-APP-000101-NDM-000231'
  tag fix_id: 'F-68817r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
