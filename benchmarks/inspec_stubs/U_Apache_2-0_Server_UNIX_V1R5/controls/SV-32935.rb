control 'SV-32935' do
  title 'A private web server must be located on a separate controlled access subnet.'
  desc 'Private web servers, which host sites that serve controlled access data, must be protected from outside threats in addition to insider threats. Insider threat may be accidental or intentional but, in either case, can cause a disruption in service of the web server. To protect the private web server from these threats, it must be located on a separate controlled access subnet and must not be a part of the public DMZ that houses the public web servers. It also cannot be located inside the enclave as part of the local general population LAN.'
  desc 'check', 'Verify the site’s network diagram and visually check the web server, to ensure that the private web server is located on a separate controlled access subnet and is not a part of the public DMZ that houses the public web servers. In addition, the private web server needs to be isolated via a controlled access mechanism from the local general population LAN.'
  desc 'fix', 'Isolate the private web server from the public DMZ and separate it from the internal general population LAN.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33627r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2243'
  tag rid: 'SV-32935r1_rule'
  tag stig_id: 'WA070 A22'
  tag gtitle: 'WA070'
  tag fix_id: 'F-29263r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'EBPW-1'
end
