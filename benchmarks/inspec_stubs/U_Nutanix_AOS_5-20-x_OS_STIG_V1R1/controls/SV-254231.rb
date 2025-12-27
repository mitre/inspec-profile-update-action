control 'SV-254231' do
  title 'Nutanix AOS must maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information. Ensuring the confidentiality of transmitted information requires the operating system to take measures in preparing information for transmission. This can be accomplished via access control and encryption. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When receiving data, operating systems need to leverage protection mechanisms such as TLS, SSL VPNs, or IPsec.'
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
  tag check_id: 'C-57716r846779_chk'
  tag severity: 'medium'
  tag gid: 'V-254231'
  tag rid: 'SV-254231r846781_rule'
  tag stig_id: 'NUTX-OS-001550'
  tag gtitle: 'SRG-OS-000426-GPOS-00190'
  tag fix_id: 'F-57667r846780_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
