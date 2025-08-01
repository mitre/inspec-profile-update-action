control 'SV-33013' do
  title 'A private web server must be located on a separate controlled access subnet.'
  desc 'Private web servers, which host sites that serve controlled access data, must be protected from outside threats in addition to insider threats. Insider threat may be accidental or intentional but, in either case, can cause a disruption in service of the web server. To protect the private web server from these threats, it must be located on a separate controlled access subnet and must not be a part of the public DMZ that houses the public web servers. It also cannot be located inside the enclave as part of the local general population LAN.'
  desc 'check', 'This check verifies that the private web server is located on a separate controlled access subnet and is not a part of the public DMZ that houses the public web servers. In addition, the private web server needs to be isolated via a controlled access mechanism from the local general population LAN.

Proposed Questions:

What devices (i.e., router, switch, or firewall) lie between the web server and Internet connectivity?
Is the private web server on a separate subnet?
Is the private web server on a LAN with servers and workstations dedicated to functions not intended for public access?

If the web server is not located inside the premise router, switch, or firewall and is not isolated via a controlled access mechanism from the general population LAN, this is a finding.'
  desc 'fix', 'Isolate the private web server from the public DMZ and separate it from the internal general population LAN. This separation must have access control in place to protect the web server from internal threats.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33695r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2243'
  tag rid: 'SV-33013r1_rule'
  tag stig_id: 'WA070 W22'
  tag gtitle: 'WA070'
  tag fix_id: 'F-29317r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'EBPW-1'
end
