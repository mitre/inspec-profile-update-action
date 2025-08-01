control 'SV-221848' do
  title 'The Oracle Linux operating system must be configured so that all networked systems use SSH for confidentiality and integrity of transmitted and received information as well as information during preparation for transmission.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered. 

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

'
  desc 'check', 'Verify SSH is loaded and active with the following command:

# systemctl status sshd
sshd.service - OpenSSH server daemon
Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled)
Active: active (running) since Tue 2015-11-17 15:17:22 EST; 4 weeks 0 days ago
Main PID: 1348 (sshd)
CGroup: /system.slice/sshd.service
1053 /usr/sbin/sshd -D

If "sshd" does not show a status of "active" and "running", this is a finding.'
  desc 'fix', 'Configure the SSH service to automatically start after reboot with the following command:

# systemctl enable sshd.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23563r419616_chk'
  tag severity: 'medium'
  tag gid: 'V-221848'
  tag rid: 'SV-221848r603260_rule'
  tag stig_id: 'OL07-00-040310'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-23552r419617_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000423-GPOS-00188', 'SRG-OS-000423-GPOS-00189', 'SRG-OS-000423-GPOS-00190']
  tag 'documentable'
  tag legacy: ['V-99435', 'SV-108539']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
