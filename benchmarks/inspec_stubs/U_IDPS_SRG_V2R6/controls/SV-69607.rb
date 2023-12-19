control 'SV-69607' do
  title 'The IDPS must quarantine and/or delete malicious code.'
  desc "Configuring the network element to delete and/or quarantine based on local organizational incident handling procedures minimizes the impact of this code on the network.

Malicious code includes, but is not limited to, viruses, worms, Trojan horses, and spyware. The code provides the ability for a malicious user to read from and write to files and folders on a computer's hard drive. Malicious code may also be able to run and attach programs, which may allow the unauthorized distribution of malicious mobile code.

Sometimes it is necessary to generate a log event and then automatically delete the malicious code; however, for critical attacks or where forensic evidence is deemed necessary, the preferred action is for the file to be quarantined for further investigation.

This requirement is limited to network elements that perform security functions, such as ALG and IDPS."
  desc 'check', 'Verify the IDPS quarantines and/or delete malicious code.

If the IDPS does not quarantine and/or delete malicious code, this is a finding.'
  desc 'fix', 'Configure the IDPS to quarantine and/or delete malicious code.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55985r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55361'
  tag rid: 'SV-69607r1_rule'
  tag stig_id: 'SRG-NET-000249-IDPS-00221'
  tag gtitle: 'SRG-NET-000249-IDPS-00221'
  tag fix_id: 'F-60229r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
