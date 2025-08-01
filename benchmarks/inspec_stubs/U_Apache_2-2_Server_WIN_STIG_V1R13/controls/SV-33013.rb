control 'SV-33013' do
  title 'A private web server must be located on a separate controlled access subnet.'
  desc 'Private web servers, which host sites that serve controlled access data, must be protected from outside threats in addition to insider threats. Insider threat may be accidental or intentional but, in either case, can cause a disruption in service of the web server. To protect the private web server from these threats, it must be located on a separate controlled access subnet and must not be a part of the public DMZ that houses the public web servers. It also cannot be located inside the enclave as part of the local general population LAN.'
  desc 'check', 'This check verifies that the private web server is located on a separate controlled access subnet and is not a part of the public DMZ that houses the public web servers. In addition, the private web server needs to be isolated via a controlled access mechanism from the local general population LAN.

Interview the ISSO and confirm with the SA, the Web Manager, or the individual in an equivalent role. Ask for the web server’s documented procedures and processes.

Verify the documented procedures and processes include verbiage and a diagram clearly showing what devices (router, switch, firewall) lie between the private web server and the Internet, showing the private web server’s location on a separate subnet dedicated to functions not intended for public access. 

If the documented procedures and processes do include verbiage and/or do not include a diagram clearly showing what devices (router, switch, firewall) lie between the private web server and the Internet, showing the private web server’s location on a separate subnet dedicated to functions not intended for public access, this is a finding.'
  desc 'fix', 'Isolate the private web server from the public DMZ and separate it from the internal general population LAN. This separation must have access control in place to protect the web server from internal threats.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33695r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2243'
  tag rid: 'SV-33013r2_rule'
  tag stig_id: 'WA070 W22'
  tag gtitle: 'WA070'
  tag fix_id: 'F-29317r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
