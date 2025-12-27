control 'SV-68713' do
  title 'The ALG that is part of a CDS must allow privileged administrators to configure and make changes to all security policy filters that are used to enforce information flow control.'
  desc 'The use of security policy filters provides protection for the confidentiality of data by restricting the flow of data. The capability to configure policy filters allows the ALG to enforce more granular security policies to meet complex and changing mission needs.

Policy filters enforce organizational security policy as it pertains to controlling data flow. Security policy filters can address data structures and content. These filters may include dirty word filters, file type checking filters, structured data filters, unstructured data filters, metadata content filters, and hidden content filters.

The cross domain solution must be configured to restrict management access according to the privilege level the user has been granted. Authorization to configure security policies requires the highest privilege level. This control requires the device have the capability for privileged administrators to configure security filters and to reconfigure these policies as needed to support changes in security policy.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG allows privileged administrators to configure and make changes to all security policy filters that are used to enforce information flow control.

If the ALG does not allow privileged administrators to configure and make changes to all security policy filters that are used to enforce information flow control, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to allow privileged administrators to configure and make changes to all security policy filters that are used to enforce information flow control.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55083r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54467'
  tag rid: 'SV-68713r1_rule'
  tag stig_id: 'SRG-NET-000022-ALG-000069'
  tag gtitle: 'SRG-NET-000022-ALG-000069'
  tag fix_id: 'F-59321r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000035', 'CCI-000366']
  tag nist: ['AC-4 (11)', 'CM-6 b']
end
