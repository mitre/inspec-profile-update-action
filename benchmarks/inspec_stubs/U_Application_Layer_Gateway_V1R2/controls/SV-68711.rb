control 'SV-68711' do
  title 'The ALG that is part of a CDS must allow privileged administrators to enable/disable all security policy filters used to enforce information flow control.'
  desc 'A crucial part of any information flow control solution is the ability to enable and disable policy filters in order to respond to changes in organizational security posture and mission conditions.

This is not a requirement to restrict the capability to privileged administrators, but rather to ensure there is some means of enabling/disabling policy filters (e.g., command line or user console).

Policy filters enforce organizational security policy as it pertains to controlling data flow. Security policy filters can address data structures and content. These filters may include dirty word filters, file type checking filters, structured data filters, unstructured data filters, metadata content filters, and hidden content filters.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG allows privileged administrators to enable/disable all security policy filters used to enforce information flow control.

If the ALG is not configured to allow privileged administrators to enable/disable all security policy filters used to enforce information flow control, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to allow privileged administrators to enable/disable all security policy filters used to enforce information flow control.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55081r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54465'
  tag rid: 'SV-68711r1_rule'
  tag stig_id: 'SRG-NET-000021-ALG-000068'
  tag gtitle: 'SRG-NET-000021-ALG-000068'
  tag fix_id: 'F-59319r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000034', 'CCI-000366']
  tag nist: ['AC-4 (10)', 'CM-6 b']
end
