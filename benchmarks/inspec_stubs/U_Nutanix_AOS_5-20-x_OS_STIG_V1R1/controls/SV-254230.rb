control 'SV-254230' do
  title 'Nutanix AOS must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Ensuring the confidentiality of transmitted information requires the operating system to take measures in preparing information for transmission. This can be accomplished via access control and encryption.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, operating systems need to support transmission protection mechanisms such as TLS, SSL VPNs, or IPsec.'
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
  tag check_id: 'C-57715r846776_chk'
  tag severity: 'medium'
  tag gid: 'V-254230'
  tag rid: 'SV-254230r846778_rule'
  tag stig_id: 'NUTX-OS-001540'
  tag gtitle: 'SRG-OS-000425-GPOS-00189'
  tag fix_id: 'F-57666r846777_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
