control 'SV-223488' do
  title 'ACF2 APPLDEF GSO record if used must have supporting documentation indicating the reason it was used.'
  desc 'Failure to restrict network connectivity only to authorized systems permits inbound connections from malicious systems. It also permits outbound connections that may facilitate exfiltration of DoD data.'
  desc 'check', 'From the ACF Command screen enter:
SET CONTROL(GSO)
LIST LIKE(APPLDEF-)

If the GSO APPLDEF record does not exist, this is not a finding.

If the GSO APPLDEF record does exist and no supporting documentation is available, this is a finding.'
  desc 'fix', 'For any APPLDEF GSO record used, it must have supporting documentation indicating the reason it was used.

The APPLDEF record is optional.'
  impact 0.3
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25161r504570_chk'
  tag severity: 'low'
  tag gid: 'V-223488'
  tag rid: 'SV-223488r533198_rule'
  tag stig_id: 'ACF2-ES-000700'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25149r504571_fix'
  tag 'documentable'
  tag legacy: ['V-97675', 'SV-106779']
  tag cci: ['CCI-000368', 'CCI-000366']
  tag nist: ['CM-6 c', 'CM-6 b']
end
