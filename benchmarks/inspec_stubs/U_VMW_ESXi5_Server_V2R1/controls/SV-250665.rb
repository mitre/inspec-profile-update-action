control 'SV-250665' do
  title 'The system must ensure uniqueness of CHAP authentication secrets.'
  desc 'The mutual authentication secret for each host must be different and the secret for each client authenticating to the server must be different as well. This ensures if a single host is compromised, an attacker cannot create another arbitrary host and authenticate to the storage device. With a single shared secret, compromise of one host can allow an attacker to authenticate to the storage device.'
  desc 'check', 'From the vSphere Client, select the host, and then choose: Configuration - Storage Adaptors - iSCSI Initiator Properties - CHAP - CHAP 
(Target Authenticates Host) - determine if a different authentication secret is configured for each ESXi host.

If a different authentication secret is not configured for each ESXi host, this is a finding.

If iSCSI is not used, this is not a finding.'
  desc 'fix', 'From the vSphere Client, select the host, and then choose: Configuration - Storage Adaptors - iSCSI Initiator Properties - CHAP - CHAP 
(Target Authenticates Host) - configure the authentication secret.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54100r798992_chk'
  tag severity: 'low'
  tag gid: 'V-250665'
  tag rid: 'SV-250665r798994_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000147'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54054r798993_fix'
  tag 'documentable'
  tag legacy: ['V-39303', 'SV-51119']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
