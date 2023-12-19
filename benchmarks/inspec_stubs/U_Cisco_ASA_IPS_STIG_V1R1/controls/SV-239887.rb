control 'SV-239887' do
  title 'The Cisco ASA must be configured to block traffic from IP addresses that have a known bad reputation based on the latest reputation intelligence.'
  desc "Configuring the network element to delete and/or quarantine based on local organizational incident handling procedures minimizes the impact of this code on the network.

Malicious code includes, but is not limited to, viruses, worms, trojan horses, and spyware. The code provides the ability for a malicious user to read from and write to files and folders on a computer's hard drive. Malicious code may also be able to run and attach programs, which may allow the unauthorized distribution of malicious mobile code.

Sometimes it is necessary to generate a log event and then automatically delete the malicious code; however, for critical attacks or where forensic evidence is deemed necessary, the preferred action is for the file to be quarantined for further investigation.

This requirement is limited to network elements that perform security functions, such as ALG and IDPS."
  desc 'check', 'Step 1: Navigate to Configuration >> ASA FirePOWER Configuration >> Object Management.

Step 2: Click the Security Intelligence tab.

Step 3: Next to the Intelligence Feed, click the edit icon.

Step 4: Verify that a frequency has been selected and not disabled.

Note: The Security Intelligence block listing feature is the easiest method to maintain a blacklist. Security Intelligence uses reputation intelligence to quickly block connections to or from IP addresses, URLs, and domain names. The Intelligence Feed, which tracks IP addresses representing security threats such as malware, spam, botnets, and phishing. Because the Intelligence Feed is regularly updated, using it ensures that the system uses up-to-date information to filter malicious network traffic.

If the ASA is not configured to block traffic from IP addresses that have a known bad reputation based on the latest reputation intelligence, this is a finding.'
  desc 'fix', 'Step 1: Navigate to Configuration >> ASA FirePOWER Configuration >> Object Management.

Step 2: Click the Security Intelligence tab.

Step 3: Next to the Intelligence Feed, click the edit icon.

Step 4: Edit the Update Frequency. Choose various intervals from two hours to one week. The user can also disable feed updates.

Step 5: Click Store ASA FirePOWER Changes.'
  impact 0.5
  ref 'DPMS Target Cisco ASA IPS'
  tag check_id: 'C-43120r665972_chk'
  tag severity: 'medium'
  tag gid: 'V-239887'
  tag rid: 'SV-239887r665974_rule'
  tag stig_id: 'CASA-IP-000270'
  tag gtitle: 'SRG-NET-000249-IDPS-00221'
  tag fix_id: 'F-43079r665973_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
