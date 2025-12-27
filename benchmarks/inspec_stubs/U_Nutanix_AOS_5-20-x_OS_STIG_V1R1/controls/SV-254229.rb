control 'SV-254229' do
  title 'Nutanix AOS must protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', 'Confirm Nutanix AOS has SSH loaded and active.

$ sudo systemctl status sshd
sshd.service - OpenSSH server daemon
Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled)
Active: active (running) since Tue 2015-11-17 15:17:22 EST; 4 weeks 0 days ago
Main PID: 1348 (sshd)
CGroup: /system.slice/sshd.service
1053 /usr/sbin/sshd -D

If "sshd" does not show a status of "active" and "running", this is a finding.

If the "SSH server" package is not installed, this is a finding.'
  desc 'fix', 'Configure SSH on Nutanix AOS by running the following command:

$ sudo salt-call state.sls security/CVM/sshdCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57714r846773_chk'
  tag severity: 'medium'
  tag gid: 'V-254229'
  tag rid: 'SV-254229r846775_rule'
  tag stig_id: 'NUTX-OS-001520'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-57665r846774_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
