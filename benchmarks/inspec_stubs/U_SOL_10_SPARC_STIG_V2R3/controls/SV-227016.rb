control 'SV-227016' do
  title 'The system must not have any peer-to-peer file-sharing application installed.'
  desc 'Peer-to-peer file-sharing software can result in the unintentional exfiltration of information.  There are also many legal issues associated with these types of utilities including copyright infringement or other intellectual property issues.  The ASD Memo "Use of Peer-to-Peer (P2P) File-Sharing Applications across the DoD" states the following:

"P2P file-sharing applications are authorized for use on DoD networks with approval by the appropriate Designated Approval Authority (DAA).  Documented requirements, security architecture, configuration management process, and a training program for users are all requirements within the approval process.  The unauthorized use of application or services, including P2P applications, is prohibited, and such applications or services must be eliminated."

P2P applications include, but are not limited to, the following:

-Napster,
-Kazaa,
-ARES,
-Limewire,
-IRC Chat Relay, and
-BitTorrent.'
  desc 'check', 'Ask the SA if any peer-to-peer file-sharing applications are installed.  Some examples of these applications include:

- Napster,
- Kazaa,
- ARES,
- Limewire,
- IRC Chat Relay, and
- BitTorrent.

If any of these applications are installed, this is a finding.'
  desc 'fix', 'Uninstall the peer-to-peer file sharing application(s) from the system.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36418r602857_chk'
  tag severity: 'medium'
  tag gid: 'V-227016'
  tag rid: 'SV-227016r603265_rule'
  tag stig_id: 'GEN006040'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-36382r602858_fix'
  tag 'documentable'
  tag legacy: ['SV-12526', 'V-12025']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
