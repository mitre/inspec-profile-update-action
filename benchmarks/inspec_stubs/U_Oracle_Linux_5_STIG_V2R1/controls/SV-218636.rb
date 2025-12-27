control 'SV-218636' do
  title 'The system must not have any peer-to-peer file-sharing application installed.'
  desc 'Peer-to-peer file-sharing software can result in the unintentional exfiltration of information.  There are also many legal issues associated with these types of utilities including copyright infringement or other intellectual property issues.  The ASD Memo "Use of Peer-to-Peer (P2P) File-Sharing Applications across the DoD" states the following:

“P2P file-sharing applications are authorized for use on DOD networks with approval by the appropriate Designated Approval Authority (DAA).  Documented requirements, security architecture, configuration management process, and a training program for users are all requirements within the approval process.  The unauthorized use of application or services, including P2P applications, is prohibited, and such applications or services must be eliminated.”

P2P applications include, but are not limited to, the following:

-Napster
-Kazaa
-ARES
-Limewire
-IRC Chat Relay
-BitTorrent'
  desc 'check', 'Ask the SA if any peer-to-peer file-sharing applications are installed. Some examples of these applications include:

- Napster
- Kazaa
- ARES
- Limewire
- IRC Chat Relay
- BitTorrent

If any of these applications are installed, this is a finding.'
  desc 'fix', 'Uninstall the peer-to-peer file sharing application(s) from the system.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20111r562885_chk'
  tag severity: 'medium'
  tag gid: 'V-218636'
  tag rid: 'SV-218636r603259_rule'
  tag stig_id: 'GEN006040'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20109r562886_fix'
  tag 'documentable'
  tag legacy: ['V-12025', 'SV-64127']
  tag cci: ['CCI-000381', 'CCI-001436']
  tag nist: ['CM-7 a', 'AC-17 (8)']
end
