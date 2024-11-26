control 'SV-239400' do
  title 'ESX Agent Manager must be configured with the appropriate ports.'
  desc 'Web servers provide numerous processes, features, and functionalities that use TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system. The ports that the ESX Agent Manager listens on are configured in the "catalina.properties" file and must be verified as accurate to their shipping state.'
  desc 'check', "At the command prompt, execute the following command:

# grep 'bio.http.port' /etc/vmware-eam/catalina.properties

Expected result:

bio.http.port=15005

If the output of the command does not match the expected result, this is a finding."
  desc 'fix', 'Navigate to and open: 

/etc/vmware-eam/catalina.properties

Navigate to the ports specification section.

Set the ESX Agent Manager port specifications according to the following:

bio.http.port=15005'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 EAM Tomcat'
  tag check_id: 'C-42633r674692_chk'
  tag severity: 'medium'
  tag gid: 'V-239400'
  tag rid: 'SV-239400r674694_rule'
  tag stig_id: 'VCEM-67-000029'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-42592r674693_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
