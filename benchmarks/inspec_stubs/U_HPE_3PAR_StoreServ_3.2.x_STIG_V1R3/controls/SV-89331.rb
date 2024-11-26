control 'SV-89331' do
  title 'The storage system in a hardened configuration must be configured to encrypt data associated with the Remote Copy feature.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.

Facilitating the confidentiality and integrity of transmitted information requires the operating system to take measures in preparing information for transmission. This can be accomplished via encryption.

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.'
  desc 'check', 'Determine if the Remote Copy feature is running via the following command:

cli% showrcopy
Remote Copy is not configured on this system.

If Remote Copy is not configured, this requirement is not applicable.

If the Status is "Started" inspect the data path to and from the host for the proper use of a Nokia 1830 encrypting switch.

If all data does not traverse this switch, this is a finding.'
  desc 'fix', 'Properly configure a Nokia 1830 encrypting switch to encrypt all data related to the Remote Copy feature or disable the Remote Copy feature with the following command:

cli% stoprcopy'
  impact 0.7
  ref 'DPMS Target HPE 3PAR OS 3.2.2'
  tag check_id: 'C-74543r1_chk'
  tag severity: 'high'
  tag gid: 'V-74657'
  tag rid: 'SV-89331r1_rule'
  tag stig_id: 'HP3P-32-001005'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-81257r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
