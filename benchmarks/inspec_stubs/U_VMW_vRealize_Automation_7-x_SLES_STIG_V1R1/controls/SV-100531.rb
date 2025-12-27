control 'SV-100531' do
  title 'The SLES for vRealize must employ a deny-all, allow-by-exception firewall policy for allowing connections to other systems.'
  desc 'Failure to restrict network connectivity only to authorized systems permits inbound connections from malicious systems. It also permits outbound connections that may facilitate exfiltration of DoD data.'
  desc 'check', 'Check firewall configuration with the following command:

iptables --list|grep -e OUTPUT -e INPUT -e FORWARD

If employ a deny-all, allow-by-exception firewall policy for allowing connections to other systems, this is a finding.'
  desc 'fix', 'Configure the SLES for vRealize to employ a deny-all, allow-by-exception firewall policy for allowing connections to other systems.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89573r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89881'
  tag rid: 'SV-100531r1_rule'
  tag stig_id: 'VRAU-SL-001550'
  tag gtitle: 'SRG-OS-000480-GPOS-00231'
  tag fix_id: 'F-96623r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002080']
  tag nist: ['CM-6 b', 'CA-3 (5)']
end
