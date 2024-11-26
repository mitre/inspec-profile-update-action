control 'SV-32634' do
  title 'A private web server must be located on a separate controlled access subnet.'
  desc 'Private web servers, which host sites that serve controlled access data, must be protected from outside threats in addition to insider threats, which can cause a disruption in service of the web server. To protect the private web server from these threats, it must be located on a separately controlled access subnet and must not be a part of the public DMZ that houses the public web servers. It also cannot be located inside the enclave as part of the local general population LAN.'
  desc 'check', 'Perform a check of the site’s network diagram and a visual check of the web server. The private web server must be located on a separately controlled access subnet and not part of the public DMZ that houses the public web servers. In addition, the private web server needs to be isolated via a controlled access mechanism from the local general population LAN. If the web server is not located inside the premise router, switch, or firewall, and is not isolated via a controlled access mechanism from the general population LAN, this is a finding.'
  desc 'fix', 'Isolate the private web server from the public DMZ and separate it from the internal general population LAN. This separation must have access control in place to protect the web server from internal threats.'
  impact 0.5
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-33505r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2243'
  tag rid: 'SV-32634r2_rule'
  tag stig_id: 'WA070 IIS7'
  tag gtitle: 'WA070'
  tag fix_id: 'F-29203r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
