control 'SV-240248' do
  title 'Lighttpd must use SSL/TLS protocols in order to secure passwords during transmission from the client.'
  desc 'Data used to authenticate, especially passwords, needs to be protected at all times, and encryption is the standard method for protecting authentication data during transmission. Data used to authenticate the vAMI admin must be sent to Lighttpd via SSL/TLS.

To ensure that Lighttpd is using SSL/TLS, the ssl.engine must be enabled.'
  desc 'check', %q(At the command prompt, execute the following command:

grep '^ssl.engine' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value of "ssl.engine" is not set to "enable", this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf file

Configure the lighttpd.conf file with the following:

ssl.engine = "enable"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43481r667919_chk'
  tag severity: 'medium'
  tag gid: 'V-240248'
  tag rid: 'SV-240248r879609_rule'
  tag stig_id: 'VRAU-LI-000225'
  tag gtitle: 'SRG-APP-000172-WSR-000104'
  tag fix_id: 'F-43440r667920_fix'
  tag 'documentable'
  tag legacy: ['SV-99927', 'V-89277']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
