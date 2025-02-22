control 'SV-69605' do
  title 'The IDPS must perform real-time monitoring of files from external sources at network entry/exit points.'
  desc 'Real-time monitoring of files from external sources at network entry/exit points helps to detect covert malicious code before it is downloaded to or executed by internal and external endpoints. Using malicious code, such as viruses, worms, Trojan horses, and spyware, an attacker may gain access to sensitive data and systems.

IDPSs innately meet this requirement for real-time scanning for malicious code when properly configured to meet the requirements of this SRG. However, most products perform communications traffic inspection at the packet level.'
  desc 'check', 'Verify the IDPS performs real-time monitoring of files from external sources at network entry/exit points.

If the IDPS does not perform real-time monitoring of files from external sources at network entry/exit points, this is a finding.'
  desc 'fix', 'Configure the IDPS to perform real-time monitoring of files from external sources at network entry/exit points.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55983r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55359'
  tag rid: 'SV-69605r1_rule'
  tag stig_id: 'SRG-NET-000248-IDPS-00206'
  tag gtitle: 'SRG-NET-000248-IDPS-00206'
  tag fix_id: 'F-60227r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
