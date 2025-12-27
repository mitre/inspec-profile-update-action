control 'SV-215284' do
  title 'AIX must protect the confidentiality and integrity of transmitted information during preparation for transmission and maintain the confidentiality and integrity of information during reception and disable all non-encryption network access methods.'
  desc 'Without protection of the transmitted or received information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered. 

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

'
  desc 'check', 'Run the following command to check if SSH server package is installed:
 
# lslpp -l | grep -i ssh 
openssh.base.client     6.0.0.6201  COMMITTED  Open Secure Shell Commands
openssh.base.server     6.0.0.6201  COMMITTED  Open Secure Shell Server
openssh.man.en_US       6.0.0.6201  COMMITTED  Open Secure Shell

If package "openssh.base.server" is not installed, this is a finding.

Run the following command to check if the SSH daemon is running:

# lssrc -s sshd | grep active
sshd             ssh              3670408      active

If "sshd" is "inoperative", this is a finding.'
  desc 'fix', 'If the SSH server package is not installed, install "openssh.base.server" package and config the SSH daemon. 

If the ssh demon is not "active", run the following command to start it:
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16482r294303_chk'
  tag severity: 'medium'
  tag gid: 'V-215284'
  tag rid: 'SV-215284r508663_rule'
  tag stig_id: 'AIX7-00-002097'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-16480r294304_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag legacy: ['V-91561', 'SV-101659']
  tag cci: ['CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-002890', 'CCI-003123']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)', 'MA-4 (6)', 'MA-4 (6)']
end
