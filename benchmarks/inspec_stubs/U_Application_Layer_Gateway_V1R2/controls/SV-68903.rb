control 'SV-68903' do
  title 'The ALG providing content filtering must be configured to perform real-time scans of files from external sources at network entry/exit points as they are downloaded and prior to being opened or executed.'
  desc "Malicious code includes viruses, worms, Trojan horses, and Spyware. The code provides the ability for a malicious user to read from and write to files and folders on a computer's hard drive. Malicious code may also be able to run and attach programs, which may allow the unauthorized distribution of malicious mobile code. Once this code is installed on endpoints within the network, unauthorized users may be able to breach firewalls and gain access to sensitive data.

To guard against malicious code, real-time scans must be performed on files from external sources as they are downloaded and prior to being opened or executed.

This requirement is limited to ALGs, web content filters, and packet inspection firewalls that perform malicious code detection as part of their functionality."
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functionality, this is not applicable.

Verify the ALG performs real-time scans of files from external sources at network entry/exit points as they are downloaded and prior to being opened or executed.

If the ALG does not perform real-time scans of files from external sources at network entry/exit points as they are downloaded and prior to being opened or executed, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to perform real-time scans of files from external sources at network entry/exit points as they are downloaded and prior to being opened or executed.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55277r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54657'
  tag rid: 'SV-68903r1_rule'
  tag stig_id: 'SRG-NET-000248-ALG-000133'
  tag gtitle: 'SRG-NET-000248-ALG-000133'
  tag fix_id: 'F-59513r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
