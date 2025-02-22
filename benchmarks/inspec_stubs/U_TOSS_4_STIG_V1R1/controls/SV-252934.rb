control 'SV-252934' do
  title 'All TOSS networked systems must have and implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

'
  desc 'check', 'Verify that the SSH package is installed:

$ rpm -q openssh-server
openssh-server-8.0p1-10.el8_4.2.x86_64

If the "SSH server" package is not installed, this is a finding.

Verify SSH is loaded and active with the following commands:

$ sudo systemctl is-active sshd
active

$ sudo systemctl is-enabled sshd
enabled

If "sshd" does not show a status of "active" and "enabled", this is a finding.'
  desc 'fix', 'Install the SSH server package onto the host with the following command:

$ sudo yum install openssh-server

Configure the SSH service to automatically start now and after each reboot with the following command:

$ sudo systemctl enable --now sshd.service'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56387r824124_chk'
  tag severity: 'medium'
  tag gid: 'V-252934'
  tag rid: 'SV-252934r824126_rule'
  tag stig_id: 'TOSS-04-010280'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-56337r824125_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)']
end
