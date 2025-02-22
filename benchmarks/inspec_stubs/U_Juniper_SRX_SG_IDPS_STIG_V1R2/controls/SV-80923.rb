control 'SV-80923' do
  title 'The Juniper Networks SRX Series Gateway IDPS must perform real-time monitoring of files from external sources at network entry/exit points.'
  desc 'Real-time monitoring of files from external sources at network entry/exit points helps to detect covert malicious code before it is downloaded to or executed by internal and external endpoints. Using malicious code, such as viruses, worms, Trojan horses, and spyware, an attacker may gain access to sensitive data and systems.

IDPSs innately meet this requirement for real-time scanning for malicious code when properly configured to meet the requirements of this STIG. However, most products perform communications traffic inspection at the packet level.'
  desc 'check', 'Verify a dynamic custom attack group which includes attack objects for malicious code monitoring of files.

show security idp dynamic-attack-group

If a custom attack group exists containing members which include malicious code attack categories, this is a finding.'
  desc 'fix', 'Configure a dynamic custom attack group which includes attack objects for malicious code monitoring of files. There are many ways to accomplish this; thus, the following is only an example:

[edit] 
security idp dynamic-attack-group Malicious-Activity
set category values [ SHELLCODE VIRUS WORMS SPYWARE TROJAN]'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67079r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66433'
  tag rid: 'SV-80923r1_rule'
  tag stig_id: 'JUSX-IP-000027'
  tag gtitle: 'SRG-NET-000248-IDPS-00206'
  tag fix_id: 'F-72509r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
