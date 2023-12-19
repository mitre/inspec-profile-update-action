control 'SV-89333' do
  title 'The CIM service must use DoD-approved encryption.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.

Facilitating the confidentiality and integrity of transmitted information requires the operating system to take measures in preparing information for transmission. This can be accomplished via encryption.

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.'
  desc 'check', 'Determine if the CIM service is running with proper encryption via the following command:

cli% showcim

If the CIM service is "Disabled" and the CIM service "State" is "Inactive", this requirement is not applicable.

If the output does not report the CIM HTTP value is "Disabled", this is a finding.

If the output does not report the CIM HPPTSPort value is "5989", this is a finding.'
  desc 'fix', 'Disable unsecured CIM ports and enable secured CIM ports with the following command:

cli% setcim -http disable -https enable

Confirm the operation with "y"'
  impact 0.7
  ref 'DPMS Target HPE 3PAR OS 3.2.2'
  tag check_id: 'C-74545r1_chk'
  tag severity: 'high'
  tag gid: 'V-74659'
  tag rid: 'SV-89333r1_rule'
  tag stig_id: 'HP3P-32-001006'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-81259r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
